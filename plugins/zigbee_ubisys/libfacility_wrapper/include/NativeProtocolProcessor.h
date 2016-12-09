// NativeProtocolProcessor.h : header file
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


/////////////////////////////////////////////////////////////////////////////
// forward references

class CNativeProtocolProcessorCookie;
class EvCompactTimerService;


/////////////////////////////////////////////////////////////////////////////
// CNativeProtocolProcessor

class CNativeProtocolProcessor : public CMobileProtocolProcessor
{
	// typedefs & enums
	public:
		enum { statusSuccess, statusConnectionFailed = 0x00001000, };

	// Construction
	public:
		// Use this flavour to connect to a known facility service
		CNativeProtocolProcessor(
			ev::EventLoop &loop,
			EvCompactTimerService &timerService,
			const std::shared_ptr<CFacilityService> &pService,
			const std::shared_ptr<CMobileProtocolSession> pSession = 0);

		// Use this flavour to discover a service
		// CNativeProtocolProcessor();

	// Attributes
	public:

		// Idle handler
		const std::function<void()> m_onIdle;

		// Returns a shared instance pointer (type-cast version of m_instance)
		std::shared_ptr<CNativeProtocolProcessor> GetInstance();

	// Operations
	public:
		// Establishes a TCP connection to the server whose URL is stored in
		// the preferences
		bool Connect(const char *const pszHost, const unsigned short wPort,
			const std::function<void(unsigned int nStatus,
				std::shared_ptr<CNativeProtocolProcessor> instance)> &onConnect = nullptr,
			const std::function<void(bool bError, bool bLocallyInitiated,
				std::shared_ptr<CNativeProtocolProcessor> instance)> &onClosed = nullptr);

		// Attaches to a socket handle that has already been opened, e.g. via
		// a peer-to-peer networking service
		bool Attach(const int nSocketHandle, const std::function<void (bool bError,
			bool bLocallyInitiated,
			std::shared_ptr<CNativeProtocolProcessor> instance)> &onClosed = nullptr);

		// Replaces the handler block that is invoked when the connection is
		// closed (either intentionally or due to an error)
		void SetClosedHandler(const std::function<void(bool bError,
			bool bLocallyInitiated,
			std::shared_ptr<CNativeProtocolProcessor> instance)> &onClosed = nullptr);

		// Tears the TCP connection down and releases the instance by default
		void Close(const bool bRelease = true);

	// Overrides
	public:
		// Creates a timer (iOS run-loop timer)
		virtual void CreateTimer(const unsigned int nTimeout,
			const TIMERCALLBACK pfnCallback, void *const pArgument, void **pTimer);

		// Cancels a pending timer (and invalidates the pointer)
		virtual void CancelTimer(void *&pTimer);

		// Called when data has been received (connecton delegate override)
		virtual void OnIndicateData(CPacket &packet);

		// Triggered by events on the read stream (connecton delegate override)
		//virtual void OnReadStreamEvent(CFStreamEventType event);

		// Triggered by events on the write stream (connecton delegate override)
		//virtual void OnWriteStreamEvent(CFStreamEventType event);

		// This method is called when there are pending requests or all requests
		// have been processed. Evaluate m_requests.empty() to determine whether
		// there is network activity
		virtual void IndicateActivity();

	// Overrides
	public:
		// Releases the instance
		virtual void Release();

		// Called by the mobile protocol processor instance, after the TCP/IP
		// connection to the designated FacilityService server has been successfully
		// established
		virtual void OnServerConnectionEstablished();

		// Called by the mobile protocol processor instance, after an attempt
		// to connect to the server has failed
		virtual void OnServerConnectionFailed();

		// Called by the mobile protocol processor instance, after the TCP/IP
		// connection to the facility service  has been closed. If bError is true,
		// the connection was closed due to an error
		virtual void OnServerConnectionClosed(const bool bError,
			const bool bLocallyInitiated);

		// Executes a request
		virtual void DoExecute
			(std::shared_ptr<CFacilityServiceProtocolRequest> &request,
			const unsigned int nTimeout);

		// Notify sinks that the link is able to accept more data
		virtual void CheckAndNotifyCanAcceptData();

	// Implementation
	public:
		virtual ~CNativeProtocolProcessor();

		// Current request frame for transmission (buffer for partially
		// transferred frames)
		std::pair<CPacket, std::recursive_mutex> m_request;

		// This block is called as soon as a Connect() request has completed
		// either with success or with failure
		std::function<void(unsigned int nStatus,
			std::shared_ptr<CNativeProtocolProcessor> instance)>
			m_onConnectComplete;

		// This block is called after the connection has been established and
		// and error occured, which caused the connection to fail
		std::function<void(bool bError, bool bLocallyInitiated,
			std::shared_ptr<CNativeProtocolProcessor> instance)>
			m_onConnectionClosed;

		// Queue a request and (possibly) start transmission
		void QueueRequest(const std::shared_ptr<CFacilityServiceProtocolRequest> &request);

		// Callback function to be invoked for events on m_nSocketHandle
		// (via m_pSocketWatcher)
		void OnIO(int nEvents);

		// Attempt to write the remaining packet contents. Any written data
		// will be stripped from the packet instance. Requests the EV_WRITE
		// event if data remains to be written
		// Will invoke close handlers on error. Returns true on success, false
		// if an error occured.
		bool RequestData(CPacket &p);

		// Called on successful establishment of the connection.
		// Notifies the Delegates in m_sink and sets up internal state.
		void OnConnectionEstablished();

	protected:
		ev::EventLoop &m_loop;

		EvCompactTimerService &m_timerService;

		// A critical section for creating and cancelling timers
		std::recursive_mutex m_mutexTimer;

		// True, if the connection is closed or currently being closed
		std::pair<bool, std::recursive_mutex> m_closed;

		// Socket handle for the TCP/IP connection
		int m_nSocketHandle;

		// An IO watcher
		std::unique_ptr<ev::IOWatcher> m_pSocketWatcher;

		// This is address information that can be used to try different
		// addresses for a service, e.g. IPv4 and IPv6 address
		std::unique_ptr<CNativeProtocolProcessorCookie> m_pCookie;

		// This timer callback provides the glue logic between CCompactTimer
		// timers managed in CCompactTimerService and timer callbacks used in
		// CFacilityServiceProtocolProcessor
		static void OnTimer(void *pArgument);

		// Triggers a write to the connection
		void TriggerWrite();
};


inline std::shared_ptr<CNativeProtocolProcessor>
CNativeProtocolProcessor::GetInstance()
{
	return std::static_pointer_cast<CNativeProtocolProcessor>(m_instance);
}


/////////////////////////////////////////////////////////////////////////////
// LoadAvailableFacilities()

void LoadAvailableFacilities();
