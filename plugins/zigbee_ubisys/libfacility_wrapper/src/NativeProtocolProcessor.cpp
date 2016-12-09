// NativeProtocolProcessor.cpp : implementation file
//
// Copyright(C) 2016 ubisys technologies GmbH, Duesseldorf, Germany.
// All rights reserved.
//
// www.ubisys.de
// support@ubisys.de
//
// Protocol processor for the mobile client. Executes requests issued by the
// mobile client app. Manages the connection to the server, i.e. invokes
// appropriate callbacks, when response frames have been received, the
// connection is lost, frames have timed-out, etc.

#include <netdb.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <uuid/uuid.h>
#include <functional>
#include <cstdlib>
#include <cstring>
#include <cstddef>
#include <cassert>
#include <fstream>
#include <memory>
#include <string>
#include <array>
#include <queue>
#include <list>
#include <set>
#include <map>
#include <mutex>
#include <tuple>
#include <libev++.h>
#include "CompactFramework.h"
#include "CompactTimer.h"
#include "CompactTimerService.h"
#include "CompactXML.h"
#include "CompactXMLEx.h"
#include "Packet.h"
#include "BigUnsigned.h"
#include "BigPoint.h"
#include "IEEE802154CommonTypes.h"
#include "ZigBeeCommonTypes.h"
#include "ZigBeeAttribute.h"
#include "ZigBeeAttributeEx.h"
#include "ServiceAsset.h"
#include "FacilityService.h"
#include "FacilityServiceCryptographyProvider.h"
#include "FacilityServiceProtocol.h"
#include "FacilityServiceProtocolFrames.h"
#include "FacilityServiceProtocolProcessor.h"
#include "MobileProtocolProcessor.h"
#include "NativeProtocolProcessor.h"
#include "EvCompactTimerService.h"


using namespace std::placeholders;


/////////////////////////////////////////////////////////////////////////////
// GetPeerAddress()

static std::string to_string(struct sockaddr &address)
{
	std::string str;
	void *pAddress;

	if (address.sa_family == AF_INET)
	{
		str.resize(INET_ADDRSTRLEN);
		pAddress = &reinterpret_cast<sockaddr_in &>(address).sin_addr;
	}
	else if (address.sa_family == AF_INET6)
	{
		str.resize(INET6_ADDRSTRLEN);
		pAddress = &reinterpret_cast<sockaddr_in6 &>(address).sin6_addr;
	}
	else
		return "(unsupported)";

	if (!inet_ntop(address.sa_family, pAddress, &str.front(), str.size()))
		str = "(invalid)";

	return str;
}


static std::string GetPeerAddress(const int nSocket)
{
	struct sockaddr_storage peer;
	socklen_t cbPeer = sizeof(peer);

	return (getpeername(nSocket, reinterpret_cast<sockaddr *>(&peer), &cbPeer) != -1) ?
		to_string(reinterpret_cast<sockaddr &>(peer)) : "(unknown)";
}


/////////////////////////////////////////////////////////////////////////////
// CNativeProtocolProcessorCookie

class CNativeProtocolProcessorCookie
{
	// Construction
	public:
		CNativeProtocolProcessorCookie(struct addrinfo *pAddresses = nullptr);

	// Attributes
	public:
		// A list of addresses (IPv4, IPv6), which can be used to reach a
		// specific host
		struct addrinfo *m_pAddresses;

		// The currently attempted address
		struct addrinfo *m_pAttempt;

	// Implementation
	public:
		~CNativeProtocolProcessorCookie();
};


CNativeProtocolProcessorCookie::CNativeProtocolProcessorCookie
	(struct addrinfo *pAddresses) :
m_pAddresses(pAddresses), m_pAttempt(pAddresses)
{
}


CNativeProtocolProcessorCookie::~CNativeProtocolProcessorCookie()
{
	if (m_pAddresses)
		freeaddrinfo(m_pAddresses);
}


/////////////////////////////////////////////////////////////////////////////
// CNativeProtocolProcessor

using TimerCookie = std::tuple<CNativeProtocolProcessor::TIMERCALLBACK, void *, std::reference_wrapper<EvCompactTimerService>>;


#ifdef _DEBUG
static unsigned int nInstances = 0;
#endif

CNativeProtocolProcessor::CNativeProtocolProcessor(
	ev::EventLoop &loop,
	EvCompactTimerService &timerService,
	const std::shared_ptr<CFacilityService> &pService,
	const std::shared_ptr<CMobileProtocolSession> pSession) :
CMobileProtocolProcessor(pService, pSession), m_onConnectComplete(nullptr),
m_onConnectionClosed(nullptr), m_onIdle(nullptr), m_nSocketHandle(-1),
m_loop(loop),
m_timerService(timerService),
m_pSocketWatcher(new ev::IOWatcher(std::bind(&CNativeProtocolProcessor::OnIO,
	this, _2)))
{
	m_closed.first = false;
	m_sinks.insert(this);

	TRACE2("CNativeProtocolProcessor(%u) - %p\n", ++nInstances, this);
}


CNativeProtocolProcessor::~CNativeProtocolProcessor()
{
	std::lock_guard<std::recursive_mutex> lg(m_mutexRequests);

	TRACE4("~CNativeProtocolProcessor(%u) - %p, %u, %u\n", --nInstances, this,
		m_requests.size(), m_pendingRequests.size());

	// Need to cancel all timers, including those in base classes
	if (m_pNetworkDiscoveryTimer)
		CancelTimer(m_pNetworkDiscoveryTimer);

	ASSERT(!m_instance.use_count());
	ASSERT(!m_bServerConnection);
	ASSERT(m_nSocketHandle == -1);

	m_onConnectComplete = nullptr;
	m_onConnectionClosed = nullptr;

	TRACE1("~CNativeProtocolProcessor(%u) - done\n", nInstances);
}


void CNativeProtocolProcessor::CreateTimer(const unsigned int nTimeout,
	const TIMERCALLBACK pfnCallback, void *const pArgument,
	void **const ppReference)
{
	TimerCookie *pCookie = new TimerCookie(pfnCallback, pArgument, m_timerService);

	m_timerService.CreateTimer
		(m_timerService.CalculateTicks(nTimeout * 1000000),
		&CNativeProtocolProcessor::OnTimer, pCookie,
		reinterpret_cast<CCompactTimer **>(ppReference));
}


void CNativeProtocolProcessor::CancelTimer(void *&pTimer)
{
	if (!pTimer)
		return;

	CCompactTimer *pCTimer = reinterpret_cast<CCompactTimer *&>(pTimer);
	TimerCookie *pCookie = static_cast<TimerCookie *>(pCTimer->m_pArgument);

	m_timerService.CancelTimer(pCTimer);
	delete pCookie;
}


void CNativeProtocolProcessor::OnTimer(void *pArgument)
{
	TimerCookie *pCookie = static_cast<TimerCookie *>(pArgument);

	TIMERCALLBACK cb = std::get<0>(*pCookie);
	void *pArg = std::get<1>(*pCookie);
	EvCompactTimerService &timerService = std::get<2>(*pCookie);

	cb(const_cast<CCompactTimer *>(&timerService.GetActiveTimer()), pArg);

	delete pCookie;
}


bool CNativeProtocolProcessor::Connect(const char *const pszHost,
	const unsigned short wPort,
	const std::function<void(unsigned int nStatus,
		std::shared_ptr<CNativeProtocolProcessor> instance)> &onComplete,
	const std::function<void(bool bError, bool bLocallyInitiated,
		std::shared_ptr<CNativeProtocolProcessor> instance)> &onClosed)
{
	ASSERT(!m_bConnecting);
	ASSERT(!m_bServerConnection);
	ASSERT(m_nSocketHandle == -1);
	ASSERT(!m_onConnectComplete);
	ASSERT(!m_onConnectionClosed);
	ASSERT(!m_pCookie);

#ifdef _DEBUG
	// BLOCK: Make sure there is no request in progress before connecting
	{
		std::lock_guard<std::recursive_mutex> lg(m_request.second);

		ASSERT(m_request.first.IsEmpty());
	}
#endif

	struct addrinfo hints, *pInfo;

	// We want a TCP/IP streaming connection and don't care about IP protocol
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;

	// Create a socket from hostname and port. Hostname can be either a FQDN,
	// IPv4 address or IPv6 address. We use getaddrinfo() here, which covers
	// all of the above cases

	// Note that only the first address will be connected to. In a real
	// application, potentially all addresses need to be considered.
	const int nResult = getaddrinfo(pszHost, std::to_string(wPort).c_str(),
		&hints, &pInfo);

	if (nResult)
	{
		TRACE3("protocol processor: no address for \"%s:%04hx\" - %s\r\n",
			pszHost, wPort, gai_strerror(nResult));

		return false;
	}

	m_pCookie = std::unique_ptr<CNativeProtocolProcessorCookie>
		(new CNativeProtocolProcessorCookie(pInfo));

	// Connect to the first viable option
	while (m_pCookie->m_pAttempt && (m_nSocketHandle == -1))
	{
		const int nSocketHandle = socket(m_pCookie->m_pAttempt->ai_family,
			m_pCookie->m_pAttempt->ai_socktype,
			m_pCookie->m_pAttempt->ai_protocol);

		if (nSocketHandle == -1)
		{
			TRACE0("protocol processor: failed to create socket\r\n");
			m_pCookie->m_pAttempt = m_pCookie->m_pAttempt->ai_next;
		}
		else
			m_nSocketHandle = nSocketHandle;
	}

	m_bConnecting = true;
	m_onConnectComplete = onComplete;
	m_onConnectionClosed = onClosed;

	// Cannot make even a single attempt to connect?
	if (m_nSocketHandle == -1)
	{
		TRACE0("protocol processor: failed to establish connection\r\n");

		if (m_onConnectComplete)
		{
			m_onConnectComplete(statusConnectionFailed, GetInstance());
			m_onConnectComplete = nullptr;
		}

		return false;
	}

	// Make the socket non-blocking. We use an event-driven approach instead
	// of a multi-threaded approach, here
	fcntl(m_nSocketHandle, F_SETFL,
			fcntl(m_nSocketHandle, F_GETFL) | O_NONBLOCK);

	// Try to connect
	TRACE1("protocol processor: connecting to \"%s\"...",
			to_string(*m_pCookie->m_pAttempt->ai_addr).c_str());

	if (!connect(m_nSocketHandle, m_pCookie->m_pAttempt->ai_addr,
		m_pCookie->m_pAttempt->ai_addrlen))
	{
		HandleConnectionEvent(eventOpened);
		return true;
	}

	if (errno != EINPROGRESS)
	{
		// Connection attempt failed
		TRACE0(" cannot connect\r\n");
		close(m_nSocketHandle);
		m_nSocketHandle = -1;

		if (m_onConnectComplete)
		{
			m_onConnectComplete(statusConnectionFailed, GetInstance());
			m_onConnectComplete = nullptr;
		}

		return false;
	}

	// Subscribe to IO events (write) on the event loop to be notified
	// on completion or failure of the connection
	m_pSocketWatcher->setFd(m_nSocketHandle);
	m_pSocketWatcher->setEvents(EV_WRITE);
	m_pSocketWatcher->start(m_loop);

	TRACE0(" in progress...\r\n");

	return true;
}


bool CNativeProtocolProcessor::Attach(const int nSocketHandle,
	const std::function<void(bool bError, bool bLocallyInitiated,
	std::shared_ptr<CNativeProtocolProcessor> instance)> &onClosed)
{
	ASSERT(!m_bConnecting);
	ASSERT(!m_bServerConnection);
	ASSERT(m_nSocketHandle == -1);
	ASSERT(!m_onConnectComplete);
	ASSERT(!m_onConnectionClosed);

#ifdef _DEBUG
	// BLOCK: Make sure there is no request in progress before connecting
	{
		std::lock_guard<std::recursive_mutex> lg(m_request.second);

		ASSERT(m_request.first.IsEmpty());
	}
#endif

	// If the connection has already been closed (before the socket was
	// ready to be attached) then don't attach. Close the socket and fail.
	// This is to deal with multiple connections created concurrently in
	// an attempt find a suitable connection
	if (m_closed.first)
	{
		close(nSocketHandle);
		return false;
	}

	m_onConnectionClosed = onClosed;

	m_nSocketHandle = nSocketHandle;

	m_pSocketWatcher->setFd(m_nSocketHandle);
	m_pSocketWatcher->setEvents(EV_WRITE);
	m_pSocketWatcher->start(m_loop);

	return true;
}


void CNativeProtocolProcessor::SetClosedHandler
	(const std::function<void(bool bError, bool bLocallyInitiated,
	std::shared_ptr<CNativeProtocolProcessor> instance)> &onClosed)
{
	m_onConnectionClosed = onClosed;
}


void CNativeProtocolProcessor::Close(const bool bRelease)
{
	// BLOCK: Mark connection as closed or currently being closed
	{
		std::lock_guard<std::recursive_mutex> lg(m_closed.second);

		if (m_closed.first)
		{
			TRACE1("CNativeProtocolProcessor %p already closed\n", this);

			return;
		}

		m_closed.first = true;
	}

	// If Close() is called multiple times, i.e. on a closed object
	// during shut-down, then ignore additional attempts...
	ASSERT(m_instance);

	// Stop the watcher
	m_pSocketWatcher->stop();

	// Make sure the inbound data flow is ceased before tearing down
	// the protocol processing structures
	if (m_nSocketHandle != -1)
		close(m_nSocketHandle);

	m_nSocketHandle = -1;
	m_bServerConnection = false;
	m_bConnecting = false;

	// Clear request queues
	PurgeRequests(CFacilityServiceProtocolRequest::statusCancelled);

	// BLOCK: Purge a pending request that was in the course of being sent
	{
		std::lock_guard<std::recursive_mutex> lg(m_request.second);

		m_request.first.Detach();
	}

	// Notify sinks (only once)
	for (std::set<CFacilityServiceConnectionDelegate *>::const_iterator
		i = m_sinks.begin(); i != m_sinks.end(); i++)
	{
		(*i)->OnServerConnectionClosed(false, true);
	}

	if (bRelease)
		Release();
}


void CNativeProtocolProcessor::Release()
{
	Close(false);

	m_instance = nullptr;
}


void CNativeProtocolProcessor::OnServerConnectionEstablished()
{
	ASSERT(m_instance);

	TRACE0("protocol processor: connection established\r\n");

	TRACE1("protocol processor: connected to %s\r\n",
		GetPeerAddress(m_nSocketHandle).c_str());

	if (m_onConnectComplete)
	{
		m_onConnectComplete(statusSuccess, GetInstance());
		m_onConnectComplete = nullptr;
	}

	// Set-up the IO Watcher (read event for now, connection is writable)
	m_pSocketWatcher->stop();
	m_pSocketWatcher->setEvents(EV_READ);
	m_pSocketWatcher->start(m_loop);

	TriggerWrite();
}


void CNativeProtocolProcessor::OnServerConnectionFailed()
{
	ASSERT(m_instance);

	TRACE0("protocol processor: connection failed");

	if (m_onConnectComplete)
	{
		m_onConnectComplete(statusConnectionFailed, GetInstance());
		m_onConnectComplete = nullptr;
	}
}


void CNativeProtocolProcessor::OnServerConnectionClosed(const bool bError,
	const bool bLocallyInitiated)
{
	if (!bError)
	{
		TRACE1("protocol processor: connection closed (%s)\n",
			bLocallyInitiated ? "by local host" : "by remote host");
	}
	else
		TRACE0("protocol processor: connection closed due to an error\n");

	// Call the completion handler for Connect() in case the error occurred
	// at connection time
	if (m_onConnectComplete)
	{
		m_onConnectComplete(statusConnectionFailed, GetInstance());
		m_onConnectComplete = nullptr;
	}
	else if (m_onConnectionClosed)
	{
		m_onConnectionClosed(bError, bLocallyInitiated, GetInstance());

		// Notice that the original block remains available beyond above point
		// and thus allows the protocol processor instance to reuse the code
		// block
	}
}


void CNativeProtocolProcessor::OnIndicateData(CPacket &data)
{
	std::shared_ptr<CNativeProtocolProcessor> instance = GetInstance();

	// Forward incoming data fragment to protocol processor
	CMobileProtocolProcessor::OnDataAvailable(data);

	// Trigger transmission, in case we were waiting for a response frame
	CheckAndNotifyCanAcceptData();
}


void CNativeProtocolProcessor::CheckAndNotifyCanAcceptData()
{
	// Check if stream is open
	if (m_nSocketHandle != -1)
	{
		// TODO Confirm if CheckAndNotifyCanAcceptData() might be called
		// if no data is actually writable (otherwise an m_bCanAcceptData flag
		// would need to be introduced to check the writable state)
		CMobileProtocolProcessor::CheckAndNotifyCanAcceptData();
		TriggerWrite();
	}
}


void CNativeProtocolProcessor::TriggerWrite()
{
	std::lock_guard<std::recursive_mutex> lg(m_request.second);

	// Check if there is any left-over partial frame and try to send it now
	if (m_request.first.GetSizeEx())
	{
		RequestData(m_request.first);

		// Data remaining? EV_WRITE was requested internally, just bail out
		// and wait for the EV_WRITE event
		if (m_request.first.GetSize())
			return;
	}

	std::lock_guard<std::recursive_mutex> lg2(m_mutexRequests);

	while (!m_requests.empty())
	{
		// Pop the first request from the queue
		std::shared_ptr<CFacilityServiceProtocolRequest> request = m_requests.front();
		m_requests.pop();

		// Create a copy, store it as m_request and try to (at least partially)
		// send it
		m_request.first = request->m_request.CreateCopy();
		RequestData(m_request.first);

		// Obtain request header
		const CFacilityServiceProtocolFrame *pHeader =
			static_cast<const CFacilityServiceProtocolFrame *>
			(static_cast<const CPacket &>(request->m_request).GetData());

		// And register this request as pending
		request->m_nStatus = CFacilityServiceProtocolRequest::statusPending;
		m_pendingRequests[pHeader->m_nSequence] = request;

		// If we are not expecting any response to this request, report completion
		// (this would remove the request from m_pendingRequests)
		if (!(pHeader->m_nFlags & CFacilityServiceProtocolFrame::flagHasResponse))
		{
			CPacket response;

			// Successful completion (without response frame)
			request->Complete(CFacilityServiceProtocolRequest::statusSuccess,
				response);
		}
	}
}


void CNativeProtocolProcessor::QueueRequest
	(const std::shared_ptr<CFacilityServiceProtocolRequest> &request)
{
	request->m_nStatus = CFacilityServiceProtocolRequest::statusQueued;

	// BLOCK: Queue request under critical section lock
	{
		std::lock_guard<std::recursive_mutex> lg(m_mutexRequests);

		m_requests.push(request);

		TRACE2("protocol processor: %u requests queued, %u pending\n",
			m_requests.size(), CFacilityServiceProtocolRequest::nPendingRequests);
	}

	if (++CFacilityServiceProtocolRequest::nPendingRequests == 1)
		IndicateActivity();

	// If there is no instance or no connection, fail here
	if (!m_instance || (m_nSocketHandle == -1) || !m_bServerConnection)
	{
		CPacket response;

		request->Complete(CFacilityServiceProtocolRequest::statusConnectionError,
				response);

		return;
	}

	// Trigger transmission
	TriggerWrite();
}


void CNativeProtocolProcessor::OnIO(int nEvents)
{
	TRACE2("IO Event:%s%s\r\n",
			(nEvents & EV_READ) ? " EV_READ" : "",
			(nEvents & EV_WRITE) ? " EV_WRITE" : "");

	if (m_bConnecting)
	{
		ASSERT(!m_bServerConnection);

		// Obtain the result of the connect() attempt
		int nError;
		socklen_t cbError = sizeof(nError);
		getsockopt(m_nSocketHandle, SOL_SOCKET, SO_ERROR, &nError, &cbError);

		TRACE1("Connection attempt: %s.\r\n",
			nError ? strerror(nError) : "succeeded");

		// Stop the IO watcher
		m_pSocketWatcher->stop();

		HandleConnectionEvent(nError ? eventFailure : eventOpened);

		ASSERT(!m_bConnecting);
	}
	else
	{
		if (nEvents & EV_READ)
		{
			CPacket data(4096);

			const ssize_t nRead = read(m_nSocketHandle, data.GetData(),
				data.GetCapacity());

			// If the read operation succeeded (at least one byte), then pass
			// the data to the data indication handler. Also handle the cases
			// where the remote host gracefully closed the connection (null)
			// and an error has occured (-1). In case of errors, which are
			// non-transitional, tear-down the connection and give the
			// application a chance to either reconnect or take other action

			if (nRead > 0)
			{
				data.SetSize(nRead);
				OnIndicateData(data);
			}
			else if (!nRead)
				HandleConnectionEvent(eventClosed);
			else if ((errno != EAGAIN) && (errno != EWOULDBLOCK))
				HandleConnectionEvent(eventFailure);
		}

		if (nEvents & EV_WRITE)
		{
			// Clear the EV_WRITE flag, it will be re-set if necessary
			m_pSocketWatcher->stop();
			m_pSocketWatcher->setEvents(EV_READ);
			m_pSocketWatcher->start(m_loop);

			HandleConnectionEvent(eventCanWrite);
		}
	}
}


bool CNativeProtocolProcessor::RequestData(CPacket &p)
{
	ASSERT(m_request.first.GetSizeEx());

	ssize_t nWritten = write(m_nSocketHandle,
		m_request.first.GetData(), m_request.first.GetSize());

	ASSERT((nWritten >= 0) || (nWritten == -1));

	if (nWritten == -1)
	{
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
		{
			m_pSocketWatcher->stop();
			m_pSocketWatcher->setEvents(EV_READ | EV_WRITE);
			m_pSocketWatcher->start(m_loop);
		}
		else
		{
			HandleConnectionEvent(eventFailure);

			return false;
		}
	}
	else if (nWritten)
		m_request.first.StripHeader(nWritten);

	return true;
}


void CNativeProtocolProcessor::DoExecute
	(std::shared_ptr<CFacilityServiceProtocolRequest> &request,
	const unsigned int nTimeout)
{
	// Create a time-out timer, if timeout is not 0
	if (nTimeout)
	{
		CreateTimer(nTimeout,
			&CFacilityServiceProtocolRequest::OnTimeout, request.get(),
			&request->m_pTimer);
	}

	// Queue request
	QueueRequest(request);
}


void CNativeProtocolProcessor::IndicateActivity()
{
	// Show network activity indicator as long as we have pending requests...
	const bool bActive = CFacilityServiceProtocolRequest::nPendingRequests;

	// Could update the UI to indicate activity here (e.g. spinning wheel)

	// Invoke idle block
	if (!bActive && m_onIdle)
		m_onIdle();
}


/////////////////////////////////////////////////////////////////////////////
// Linux specific helpers

static struct timespec ConvertTimeStamp(const unsigned long long qwTimestamp)
{
	struct timespec ts;

	ts.tv_sec = qwTimestamp / 10000000;
	ts.tv_nsec = (qwTimestamp % 10000000) * 100;

	return ts;
}


static unsigned long long ConvertTimeStamp(const struct timespec &ts)
{
	return ts.tv_sec * 10000000 + (ts.tv_nsec / 100);
}


/////////////////////////////////////////////////////////////////////////////
// CFacilityInventory - Linux specific parts

bool CFacilityInventory::Store()
{
	if (m_raw.first.empty())
	{
		TRACE0("protocol processor: nothing to store");
		return false;
	}

	// Store the inventory. Notice: This is an example application. You might
	// want to do something more sophisticated, like writing to a temporary
	// file and renaming it afterwards
	std::ofstream file(m_strCacheFileName.c_str(), std::ios::binary);

	file.write(&m_raw.first.front(), m_raw.first.size());
	file.close();

	const struct timespec times[2] = { { 0, UTIME_NOW },
		ConvertTimeStamp(m_raw.second) };

	if (utimensat(AT_FDCWD, m_strCacheFileName.c_str(), times, 0) == -1)
	{
		TRACE1("protocol processor: failed to change file time (%s)\r\n",
			strerror(errno));

		return false;
	}

	m_bModified = false;

	return true;
}


bool CFacilityInventory::Load()
{
	TRACE1("protocol processor: loading inventory %s\n",
		m_strCacheFileName.c_str());

	struct stat info;

	if (stat(m_strCacheFileName.c_str(), &info) == -1)
	{
		TRACE0("protocol processor: failed to obtain file attributes\n");
		return false;
	}

	// Convert Linux file time to facility service file time
	m_raw.second = ConvertTimeStamp(info.st_mtim);

	TRACE2("protocol processor: facility inventory as of %s (%llu)",
		std::localtime(&info.st_mtime), m_raw.second);

	std::ifstream file(m_strCacheFileName.c_str(),
		std::ios::binary | std::ios::ate);

	m_raw.first.resize(file.tellg());

	file.seekg(0);
	file.read(&m_raw.first.front(), m_raw.first.size());
	file.close();

	if (!Parse(m_raw.first, m_raw.second))
		return false;

	m_bModified = false;

	return true;
}


bool CFacilityInventory::Remove()
{
	return !unlink(m_strCacheFileName.c_str());
}


/////////////////////////////////////////////////////////////////////////////
// CFacilityService - Linux specific parts

static const char szFacilityPrefix[] = "facility-";
static const char szInventoryPrefix[] = "inventory-";
static const char szCredentialsPrefix[] = "credentials-";
static const char szSuffix[] = ".xml";

static std::string MakePathName(const CFacilityService &service,
	const char *const pszPrefix = szFacilityPrefix)
{
	return pszPrefix + service.m_strSerial + szSuffix;
}


bool CFacilityService::Store(const bool bGenerateHosts)
{
	if (m_strSerial.empty())
	{
		TRACE0("protocol processor: need serial number for storing descriptor");
		return false;
	}

	if (m_raw.first.empty())
	{
		TRACE0("protocol processor: nothing to store");
		return false;
	}

	std::string strPathName = MakePathName(*this);

	// Create an XML document with the host information (IP addresses and
	// ports). This is to be removed when the facility data contains host
	// name entries
	CCompactXMLDocumentEx document;
	CCompactXMLString xml;

	document.LoadXML(m_raw.first.c_str());

	if (bGenerateHosts)
	{
		for (std::list<CFacilityServiceHost>::const_iterator
			i = m_hosts.begin(); i != m_hosts.end(); i++)
		{
			CCompactXMLElement *pHost = document.CreateElement(_CXMLT("host"));

			pHost->SetAttribute(_CXMLT("name"), i->m_strName.c_str());

			document.SetAttribute(pHost, _CXMLT("port"),
				static_cast<unsigned short>(i->m_nPort), false, false);

			document.m_pDocumentElement->AppendChild(pHost);
		}
	}

	// Update the push enrollment status
	CCompactXMLDocumentEx::SetAttribute(document.m_pDocumentElement,
		_CXMLT("push-enrollment-status"), m_nPushEnrollmentStatus);

	document.StoreXML(xml);

	std::ofstream facility(strPathName.c_str(), std::ios::binary);

	facility.write(&xml.front(), xml.size());
	facility.close();

	const struct timespec times[2] = { { 0, UTIME_NOW },
		ConvertTimeStamp(m_raw.second) };

	if (utimensat(AT_FDCWD, strPathName.c_str(), times, 0) == -1)
	{
		TRACE1("protocol processor: failed to change file time (%s)\r\n",
			strerror(errno));

		return false;
	}

	// Notice: Typically you would save the credentials not in a simple
	// file, but in a secure storage, for example the cryptographic key
	// chain store
	std::ofstream credentials(MakePathName(*this, szCredentialsPrefix),
		std::ios::binary);

	credentials.write(&m_strCredentials.front(), m_strCredentials.size());
	credentials.close();

	m_inventory.m_strCacheFileName = MakePathName(*this, szInventoryPrefix);

	m_bModified = false;

	return true;
}


bool CFacilityService::Load(const void *const pInfo)
{
	ASSERT(m_strCredentials.empty());
	ASSERT(m_strSerial.empty());
	ASSERT(m_strLocation.empty());
	ASSERT(m_strDescription.empty());

	struct stat info;

	if (stat(static_cast<const char *>(pInfo), &info) == -1)
	{
		TRACE0("protocol processor: failed to obtain file attributes\n");
		return false;
	}

	// Convert Linux file time to facility service file time
	m_raw.second = ConvertTimeStamp(info.st_mtim);

	TRACE2("protocol processor: facility info as of %s (%llu)",
		std::asctime(std::localtime(&info.st_mtime)), m_raw.second);

	std::ifstream facility(static_cast<const char *>(pInfo),
		std::ios::binary | std::ios::ate);

	if (!facility)
		return false;

	m_raw.first.resize(facility.tellg());

	facility.seekg(0);
	facility.read(&m_raw.first.front(), m_raw.first.size());
	facility.close();

	if (!Parse(m_raw.first, m_raw.second))
		return false;

	std::ifstream credentials(MakePathName(*this, szCredentialsPrefix),
		std::ios::binary | std::ios::ate);

	if (credentials)
	{
		m_strCredentials.resize(credentials.tellg());

		credentials.seekg(0);
		credentials.read(&m_strCredentials.front(), m_strCredentials.size());
		credentials.close();
	}

#ifdef _DEBUG
	if (!m_strCredentials.empty())
	{
		CCompactXMLDocument document;

		ASSERT(document.LoadXML(m_strCredentials.c_str()));
	}
#endif

	m_inventory.m_strCacheFileName = MakePathName(*this, szInventoryPrefix);

	m_bModified = false;

	return true;
}


bool CFacilityService::Remove()
{
	bool bSuccess = !unlink(MakePathName(*this, szCredentialsPrefix).c_str());

	bSuccess &= !unlink(MakePathName(*this).c_str());

#ifdef _DEBUG
	ASSERT(m_inventory.m_strCacheFileName.empty() ||
		(m_inventory.m_strCacheFileName ==
		MakePathName(*this, szInventoryPrefix)));
#endif

	if (!m_inventory.m_strCacheFileName.empty())
		bSuccess &= m_inventory.Remove();

	return bSuccess;
}


std::list<std::shared_ptr<CFacilityService>> CFacilityService::LoadAll()
{
	std::list<std::shared_ptr<CFacilityService>> services;

	dirent **ppNameList;

	const int nEntries = scandir(".", &ppNameList,
		[](const struct dirent *pEntry)->int
	{
		const size_t nLength = strlen(pEntry->d_name);

		// Make sure the string is long enough ("facility-#.xml")
		if (nLength < strlen(szFacilityPrefix) + strlen(szSuffix))
			return false;

		// We're looking for entries, which start with "facility-"...
		if (strncmp(pEntry->d_name, szFacilityPrefix, strlen(szFacilityPrefix)))
			return false;

		// ...and end in ".xml"
		return !strcmp(&pEntry->d_name[nLength - strlen(szSuffix)], szSuffix);
	}, nullptr);

	for (int nEntry = 0; nEntry < nEntries; nEntry++)
	{
		std::shared_ptr<CFacilityService> service(new CFacilityService);

		if (service->Load(ppNameList[nEntry]->d_name))
			services.push_back(service);

		free(ppNameList[nEntry]);
	}

	free(ppNameList);

	return services;
}


/////////////////////////////////////////////////////////////////////////////
// LoadAvailableFacilities()

void LoadAvailableFacilities()
{
	std::list<std::shared_ptr<CFacilityService>> services =
		CFacilityService::LoadAll();

	// Order available facilities according to user preferences
	for (auto i : services)
		CFacilityService::facilities.push_back(i);
}

