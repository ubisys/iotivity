// FacilitydInterface.cpp
//
// Copyright(C) 2016 ubisys technologies GmbH, Duesseldorf, Germany.
// All rights reserved.
//
// www.ubisys.de
// support@ubisys.de
//

/**
 * @file
 *
 * Interface to the ubisys facility service. Implements a convenience wrapper around libfacility
 * to handle connection setup etc.
 * Also provides an abstraction layer around devices and applications, which allows to wrap
 * libfacility device/application instances (which will be invalidated and replaced on an inventory
 * update.
 *
 * Inventory updates are not supported yet.
 */


#define __STDC_FORMAT_MACROS
#include <cinttypes>
#include <cassert>
#include <memory>
#include <algorithm>
#include <string>
#include <list>
#include <map>
#include <vector>
#include <set>
#include <thread>
#include <functional>
#include <queue>
#include <algorithm>
#include <mutex>
#include <sstream>
#include <iterator>
#include <iomanip>
#include <uuid/uuid.h>

#include <libev++.h>
#include <CompactXML.h>
#include <CompactXMLEx.h>
#include <CompactFramework.h>
#include <Packet.h>
#include <BigUnsigned.h>
#include <BigPoint.h>
#include <IEEE802154CommonTypes.h>
#include <ZigBeeCommonTypes.h>
#include <ZigBeeAttribute.h>
#include <ZigBeeAttributeEx.h>
#include <ServiceAsset.h>
#include <FacilityService.h>
#include "FacilityServiceCryptographyProvider.h"
#include "FacilityServiceProtocol.h"
#include "FacilityServiceProtocolFrames.h"
#include "FacilityServiceProtocolProcessor.h"
#include "MobileProtocolProcessor.h"
#include "NativeProtocolProcessor.h"

#include "logger.h"
#include "FacilitydInterface.h"

#include "CompactTimer.h"
#include "EvCompactTimerService.h"

using namespace std::placeholders;


#define TAG "ubisysFacilityIf"


// anonymous namespace
namespace {

////////////////////////////////////////////////////////////////////////
// forward declarations

class Handler;
class ApplicationImpl;


////////////////////////////////////////////////////////////////////////
// DeviceImpl
// Implementation of FacilitydInterface::Device

class DeviceImpl
: public FacilitydInterface::Device
{
    public:
        DeviceImpl(Handler &, const std::shared_ptr<CFacilityZigBeeDevice> &);

    public:
        void OnAttributeChanged(CFacilityZigBeeAttribute &attribute);
        void Update(const std::shared_ptr<CFacilityZigBeeDevice> &);

    // Overrides
    public:
        std::shared_ptr<CFacilityZigBeeDevice> GetBackedDevice() override;
        std::map<uint8_t, std::shared_ptr<FacilitydInterface::Application>> GetApplications() override;

    private:
        Handler &m_handler;

        std::shared_ptr<CFacilityZigBeeDevice> m_backedDevice;

        std::map<uint8_t, std::shared_ptr<ApplicationImpl>> m_applications;
};


////////////////////////////////////////////////////////////////////////
// ApplicationImpl
// Implementation of FacilitydInterface::Application

class ApplicationImpl
: public FacilitydInterface::Application
{
    public:
        class RegistrationCookieImpl
        : public RegistrationCookie
        {
        public:
            RegistrationCookieImpl(ApplicationImpl &app,
                    const std::multimap<uint16_t, AttributeChangeCB>::iterator i)
            : m_app(app), m_iterator(i)
            {
            }

            ~RegistrationCookieImpl()
            {
                m_app.UnregisterAttributeListener(m_iterator);
            }

        private:
            ApplicationImpl &m_app;
            std::multimap<uint16_t, AttributeChangeCB>::iterator m_iterator;
        };

    public:
        ApplicationImpl(Handler &, const std::shared_ptr<CFacilityZigBeeApplication> &);

    public:
        void OnAttributeChanged(CFacilityZigBeeAttribute &attribute);

    // Overrides
    public:
        std::shared_ptr<CFacilityZigBeeApplication> GetBackedApplication() override;
        std::set<uint16_t> GetInboundClusters() override;
        std::set<uint16_t> GetOutboundClusters() override;
        void SendZCLCommamnd(uint16_t cluster, uint8_t cmd, CPacket &payload) override;

        std::unique_ptr<RegistrationCookie>
        RegisterAttributeListener(uint16_t cluster, const AttributeChangeCB &) override;

    private:
        void UnregisterAttributeListener(const std::multimap<uint16_t, AttributeChangeCB>::iterator &i);

    private:
        Handler &m_handler;

        std::shared_ptr<CFacilityZigBeeApplication> m_backedApp;

        // Attribute listeners, per cluster
        std::multimap<uint16_t, AttributeChangeCB> m_attributeListeners;
};


////////////////////////////////////////////////////////////////////////
// CFacilityServiceEx
// Bridges CFacilityService to the Handler (to pass attribute updates)

class CFacilityServiceEx : public CFacilityService
{
    public:
        CFacilityServiceEx(Handler &h);

    public:
        void OnAttributeChanged(CFacilityZigBeeAttribute &attribute) override;

    private:
        Handler &m_handler;
};


////////////////////////////////////////////////////////////////////////
// Handler

class Handler
: public std::enable_shared_from_this<Handler>
{
    public:
        using Delegate = FacilitydInterface::Delegate;
        using Options = FacilitydInterface::Options;

    public:
        Handler(ev::EventLoop &loop, const Options &opts, Delegate &, ThreadDispatcher &mainThread);

    public:
        void TriggerConnect();

    private:
        void Connect();

        void OnConnectionSetup(
                const std::shared_ptr<CNativeProtocolProcessor> &instance);

        void OnConnectComplete(const std::shared_ptr<Handler> &guard,
                unsigned int nStatus,
                const std::shared_ptr<CNativeProtocolProcessor> &instance);

        void OnGetVersionComplete(const std::shared_ptr<Handler> &guard,
                unsigned int nStatus,
                const std::shared_ptr<CMobileProtocolProcessor> &instance);

        void OnDeriveSessionKeyComplete(
                const std::shared_ptr<Handler> &guard,
                unsigned int nStatus,
                const std::shared_ptr<CMobileProtocolProcessor> &instance);

        void OnQueryMetaDataComplete(
                const std::shared_ptr<Handler> &guard,
                unsigned int nStatus,
                const std::shared_ptr<CMobileProtocolProcessor> &instance);

        void OnAuthenticationComplete(
                const std::shared_ptr<Handler> &guard,
                unsigned int nStatus,
                const std::shared_ptr<CMobileProtocolProcessor> &instance);

        void OnEnrollmentComplete(
                const std::shared_ptr<Handler> &guard,
                unsigned int nStatus,
                const std::shared_ptr<CMobileProtocolProcessor> &instance);

        void OnStartSessionComplete(
                const std::shared_ptr<Handler> &guard,
                unsigned int nStatus,
                const std::shared_ptr<CMobileProtocolProcessor> &instance);

        void OnQueryInventoryComplete(
                const std::shared_ptr<Handler> &guard,
                unsigned int nStatus,
                const std::shared_ptr<CMobileProtocolProcessor> &instance);

        void OnQueryCachedAttributesComplete(
                const std::shared_ptr<Handler> &guard,
                unsigned int nStatus,
                const std::shared_ptr<CMobileProtocolProcessor> &instance);

        void OnConfigureEndpointComplete(
                const std::shared_ptr<Handler> &guard,
                unsigned int nStatus,
                const std::shared_ptr<CMobileProtocolProcessor> &instance);

        void HandleProtocolFailure(std::shared_ptr<CMobileProtocolProcessor>, const char *);

        void HandleInventory(const CFacilityInventory &);

    public:
        void SendZCLCommand(FacilitydInterface::Application &app,
                uint16_t cluster, uint8_t cmd, CPacket &payload);

        // Invoked by CFacilityServiceEx, on the facility thread
        void OnAttributeChanged(CFacilityZigBeeAttribute &attribute);

    private:
        ev::EventLoop &m_loop;

        Delegate &m_delegate;

        ThreadDispatcher &m_mainThread;

        EvCompactTimerService m_timerService;

        FacilitydInterface::Options m_options;

        std::shared_ptr<CFacilityService> m_pService;
        std::shared_ptr<CMobileProtocolSession> m_pSession;

        bool m_bAutoReconnect = false;

        std::list<std::shared_ptr<CNativeProtocolProcessor>> m_processors;

        std::map<unsigned int, std::shared_ptr<DeviceImpl>> m_devices;

        std::map<CFacilityZigBeeDevice *, DeviceImpl*> m_mapDevices;
};


////////////////////////////////////////////////////////////////////////
// ApplicationImpl

ApplicationImpl::ApplicationImpl(Handler &h, const std::shared_ptr<CFacilityZigBeeApplication> &app)
: m_handler(h), m_backedApp(app)
{

}


void ApplicationImpl::OnAttributeChanged(CFacilityZigBeeAttribute &attribute)
{
    OIC_LOG_V(INFO, TAG, "application attribute changed for cluster %04x", attribute.m_cluster.m_wClusterID);

    // Dispatch to any registered listers (per-cluster)
    uint16_t cluster = attribute.m_cluster.m_wClusterID;
    auto r = m_attributeListeners.equal_range(cluster);
    for (auto i = r.first; i != r.second; i++)
        i->second(attribute);
}


std::shared_ptr<CFacilityZigBeeApplication> ApplicationImpl::GetBackedApplication()
{
    return m_backedApp;
}


std::set<uint16_t> ApplicationImpl::GetInboundClusters()
{
    std::set<uint16_t> c;
    auto inbound = m_backedApp->m_inbound;
    for (const auto &p : inbound)
        c.insert(p.first);
    return c;
}


std::set<uint16_t> ApplicationImpl::GetOutboundClusters()
{
    // TODO
    std::set<uint16_t> c;
    return c;
}


void ApplicationImpl::SendZCLCommamnd(uint16_t cluster, uint8_t cmd, CPacket &payload)
{
    m_handler.SendZCLCommand(*this, cluster, cmd, payload);
}


std::unique_ptr<ApplicationImpl::RegistrationCookie>
ApplicationImpl::RegisterAttributeListener(uint16_t cluster, const AttributeChangeCB &cb)
{
    auto i = m_attributeListeners.insert(std::make_pair(cluster, cb));
    return std::unique_ptr<ApplicationImpl::RegistrationCookie>(new RegistrationCookieImpl(*this, i));
}


void ApplicationImpl::UnregisterAttributeListener(const std::multimap<uint16_t, AttributeChangeCB>::iterator &i)
{
    m_attributeListeners.erase(i);
}


////////////////////////////////////////////////////////////////////////
// DeviceImpl

DeviceImpl::DeviceImpl(Handler &h, const std::shared_ptr<CFacilityZigBeeDevice> &dev)
: m_handler(h), m_backedDevice(dev)
{
   for (const auto &p : dev->m_applications)
       m_applications.insert(std::make_pair(p.first, std::make_shared<ApplicationImpl>(m_handler, p.second)));
}


void DeviceImpl::Update(const std::shared_ptr<CFacilityZigBeeDevice> &dev)
{
    m_backedDevice = dev;

    // TODO Update applications
}


void DeviceImpl::OnAttributeChanged(CFacilityZigBeeAttribute &attribute)
{
    uint8_t nEndpoint = attribute.m_cluster.m_application.m_nEndpoint;

    auto i = m_applications.find(nEndpoint);
    if (i == m_applications.end())
        OIC_LOG(WARNING, TAG, "Attribute change notification for unknown application");

    i->second->OnAttributeChanged(attribute);
}


std::shared_ptr<CFacilityZigBeeDevice> DeviceImpl::GetBackedDevice()
{
    return m_backedDevice;
}


std::map<uint8_t, std::shared_ptr<FacilitydInterface::Application>> DeviceImpl::GetApplications()
{
    std::map<uint8_t, std::shared_ptr<FacilitydInterface::Application>> m(m_applications.begin(), m_applications.end());

    return m;

}


CFacilityServiceEx::CFacilityServiceEx(Handler &h)
: m_handler(h)
{
}


void CFacilityServiceEx::OnAttributeChanged(CFacilityZigBeeAttribute &attribute)
{
    m_handler.OnAttributeChanged(attribute);
};


////////////////////////////////////////////////////////////////////////
// Handler

Handler::Handler(ev::EventLoop &loop, const Options &opts, Delegate &d, ThreadDispatcher &mainThread)
: m_loop(loop),
  m_delegate(d),
  m_mainThread(mainThread),
  m_timerService(loop),
  m_options(opts),
  m_pService(std::make_shared<CFacilityServiceEx>(*this))
{
}


void Handler::TriggerConnect()
{
    m_pService->m_hosts.push_back(CFacilityServiceHost(m_options.m_host.c_str(), m_options.m_nPort));
    Connect();
}


void Handler::Connect()
{
    // Don't allow automatic reconnects until we're connected
    m_bAutoReconnect = false;

    // Attempt to connect via all known host addresses simultaneously...
    for (std::list<CFacilityServiceHost>::const_iterator
        i = m_pService->m_hosts.begin(); i != m_pService->m_hosts.end(); i++)
    {
        // Create a new native protocol processor instance. Don't foreget
        // to call Release() on this instance
        CNativeProtocolProcessor *pProcessor =
            new CNativeProtocolProcessor(m_loop, m_timerService, m_pService, m_pSession);

        m_processors.push_back(pProcessor->GetInstance());

        // Subscribe to inventory changes
        pProcessor->m_onInventoryAvailable =
            [](const std::shared_ptr<CMobileProtocolProcessor> &instance)
        {
            OIC_LOG(INFO, TAG, "notification: new inventory available");
        };

        auto guard = shared_from_this();
        pProcessor->Connect(i->m_strName.c_str(), i->m_nPort,
            std::bind(&Handler::OnConnectComplete, this, guard, _1, _2),
            [this, guard](bool bError, bool bLocallyInitiated,
                const std::shared_ptr<CNativeProtocolProcessor> &instance)
        {
            OIC_LOG_V(WARNING, TAG, "connection closed (error = %s, initiator = %s host)",
                bError ? "true" : "false",
                bLocallyInitiated ? "local" : "remote");

            // You might want to reconnect if the remote host closed the
            // connection (which it will do after a period of inactivity)
            if (!bLocallyInitiated && m_bAutoReconnect)
                Connect();

            // Always close and release the connection instance
            instance->Close();
        });
    }
}


void Handler::OnConnectionSetup(const std::shared_ptr<CNativeProtocolProcessor> &instance)
{
    OIC_LOG(INFO, TAG, "Connection established");

    HandleInventory(m_pService->m_inventory);
}


void Handler::OnConnectComplete(const std::shared_ptr<Handler> &guard,
    unsigned int nStatus,
    const std::shared_ptr<CNativeProtocolProcessor> &instance)
{
    OIC_LOG_V(INFO, TAG, "connect complete. status = %u", nStatus);


    if (!nStatus)
    {
        OIC_LOG(INFO, TAG, "Negotiating protocol...");
        instance->GetVersion(std::bind(&Handler::OnGetVersionComplete, this, guard, _1, _2));
    }
    else
    {
        HandleProtocolFailure(instance, "failed to connect");
    }
}


void Handler::OnGetVersionComplete(const std::shared_ptr<Handler> &guard,
        unsigned int nStatus,
        const std::shared_ptr<CMobileProtocolProcessor> &instance)
{
    OIC_LOG_V(INFO, TAG, "version request complete. status = %u", nStatus);

    if (!nStatus)
    {
        OIC_LOG(INFO, TAG, "Securing connection...");
        instance->DeriveSessionKey(std::bind(&Handler::OnDeriveSessionKeyComplete, this, guard, _1, _2));
    }
    else
        HandleProtocolFailure(instance, "failed to get version");
}


void Handler::OnDeriveSessionKeyComplete(
        const std::shared_ptr<Handler> &guard,
        unsigned int nStatus,
        const std::shared_ptr<CMobileProtocolProcessor> &instance)
{
    OIC_LOG_V(INFO, TAG, "session key derivation complete. status = %u", nStatus);

    if (!nStatus)
    {
        OIC_LOG(INFO, TAG, "Refreshing...");
        instance->QueryMetaData(std::bind(&Handler::OnQueryMetaDataComplete, this, guard, _1, _2));
    }
    else
        HandleProtocolFailure(instance, "failed to derive session key");
}


void Handler::OnQueryMetaDataComplete(
        const std::shared_ptr<Handler> &guard,
        unsigned int nStatus,
        const std::shared_ptr<CMobileProtocolProcessor> &instance)
{
    OIC_LOG_V(INFO, TAG, "meta data query complete. status = %u", nStatus);

    if (!nStatus)
    {
        // If we have more than one protocol processor instance, shut
        // down the remaining ones, because we are not going to need
        // them (we have a suitable connection at this point)
        if (m_processors.size() > 1)
        {
            // When dropping a processor, first remove it from the list
            // of processors before calling Close() to avoid a situation
            // where the close handler invoked by PurgeRequests() would
            // attempt to access an invalid iterator
            std::list<std::shared_ptr<CNativeProtocolProcessor>> shutdown;

            for (auto i = m_processors.begin(); i != m_processors.end(); )
            {
                if (*i != instance)
                {
                    shutdown.push_back(*i);
                    i = m_processors.erase(i);
                }
                else
                    i++;
            }

            for (auto i : shutdown)
                i->Close();
        }

        // Do we have modified meta data available? Store the new meta
        // data (will also clear the modified flag)
        if (instance->m_pService->m_bModified)
            instance->m_pService->Store();

        // If there is another entry with the same serial number,
        // then merge both entries by creating a union of host names
        // and keeping the credentials (if any)
        for (auto i : CFacilityService::facilities)
        {
            if (instance->m_pService->CheckAndMerge(*i))
            {
                // Store merged service information
                VERIFY(instance->m_pService->Store());
                break;
            }
        }

        // If this is a new service instance and we don't have credentials,
        // we have to enroll now
        if (instance->m_pService->m_strCredentials.empty())
        {
            const std::string strCode = "0000";

            // ... and enroll with the facility service
            instance->Enroll(strCode.c_str(),
                    std::bind(&Handler::OnEnrollmentComplete, this, guard, _1, _2));
        }
        else
        {
            OIC_LOG(INFO, TAG, "Authenticating...");

            // Authenticate using the credentials on record
            instance->Authenticate(
                    std::bind(&Handler::OnAuthenticationComplete, this, guard, _1, _2));
        }
    }
    else
        HandleProtocolFailure(instance, "failed to query meta data");
}


void Handler::OnAuthenticationComplete(
        const std::shared_ptr<Handler> &guard,
        unsigned int nStatus,
        const std::shared_ptr<CMobileProtocolProcessor> &instance)
{
    OIC_LOG_V(INFO, TAG, "authentication complete. status = %u", nStatus);

    if (!nStatus)
    {
        OIC_LOG(INFO, TAG, "Starting session...");

        // Update the facility server's view on this device...
        instance->StartSession(
                std::bind(&Handler::OnStartSessionComplete, this, guard, _1, _2));
    }
    else
        HandleProtocolFailure(instance, "failed to authenticate");
}


void Handler::OnEnrollmentComplete(
        const std::shared_ptr<Handler> &guard,
        unsigned int nStatus,
        const std::shared_ptr<CMobileProtocolProcessor> &instance)
{
    OIC_LOG_V(INFO, TAG, "enrollment complete. status = %u", nStatus);

    if (!nStatus)
    {
        // Store facility information, including credentials
        VERIFY(instance->m_pService->Store());

        // Proceed as if authentication completed...
        OnAuthenticationComplete(guard, nStatus, instance);
    }
    else
        HandleProtocolFailure(instance, "failed to enroll");
}


void Handler::OnStartSessionComplete(
        const std::shared_ptr<Handler> &guard,
        unsigned int nStatus,
        const std::shared_ptr<CMobileProtocolProcessor> &instance)
{
    OIC_LOG_V(INFO, TAG, "start session complete. status = %u", nStatus);

    if (!nStatus)
    {
        // Retrieve the current inventory
        instance->QueryInventory(
                std::bind(&Handler::OnQueryInventoryComplete, this, guard, _1, _2));
    }
    else
        HandleProtocolFailure(instance, "failed to start session");
}


void Handler::OnQueryInventoryComplete(
    const std::shared_ptr<Handler> &guard,
    unsigned int nStatus,
    const std::shared_ptr<CMobileProtocolProcessor> &instance)
{
    OIC_LOG_V(INFO, TAG, "query inventory complete. status = %u", nStatus);

    if (!nStatus)
    {
        ASSERT(m_processors.size() == 1);
        ASSERT(m_processors.front() == instance);
        m_processors.clear();

        if (instance->m_pService->m_inventory.m_bModified)
            VERIFY(instance->m_pService->m_inventory.Store());

        instance->QueryCachedAttributes(
                std::bind(&Handler::OnQueryCachedAttributesComplete, this, guard, _1, _2));
    }
    else
        HandleProtocolFailure(instance, "failed to query inventory");
}


void Handler::OnQueryCachedAttributesComplete(
        const std::shared_ptr<Handler> &guard,
        unsigned int nStatus,
        const std::shared_ptr<CMobileProtocolProcessor> &instance)
{
    OIC_LOG_V(INFO, TAG, "query cached attributes complete. status = %u", nStatus);

    if (!nStatus)
    {
        OIC_LOG_V(INFO, TAG, "Configuring adapter...");

        // Do we need to configure an endpoint or can we just reuse a previous
        // session?
        if (instance->m_pSession->m_endpoints.empty())
        {
            // Configure a new ZigBee endpoint for this application...
            instance->ConfigureEndpoint(
                    std::bind(&Handler::OnConfigureEndpointComplete, this, guard, _1, _2));
        }
        else
            OnConfigureEndpointComplete(guard, nStatus, instance);
    }
    else
        HandleProtocolFailure(instance, "failed to query cached attributes");
}


void Handler::OnConfigureEndpointComplete(
        const std::shared_ptr<Handler> &guard,
        unsigned int nStatus,
        const std::shared_ptr<CMobileProtocolProcessor> &instance)
{
    OIC_LOG_V(INFO, TAG, "configure endpoint complete. status = %u", nStatus);

    if (!nStatus)
    {
        instance->m_pService->m_processor = instance;

        // Connection established at this point
        OnConnectionSetup(std::static_pointer_cast<CNativeProtocolProcessor>(instance));
    }
    else
        HandleProtocolFailure(instance, "failed to configure endpoint");
}


void Handler::HandleProtocolFailure(std::shared_ptr<CMobileProtocolProcessor>, const char *msg)
{
    OIC_LOG_V(INFO, TAG, "Protocol failure: %s", msg);
}


void Handler::HandleInventory(const CFacilityInventory &inv)
{
    const auto &devices = m_pService->m_inventory.m_devices;

    std::set<unsigned int> existing;
    for (const auto &p : m_devices)
        existing.insert(p.first);

    std::set<unsigned int> current;
    for (const auto &p : devices)
        current.insert(p.first);

    // Determine the set of new devices added
    std::set<unsigned int> added;
    std::set_difference(
            current.begin(), current.end(),
            existing.begin(), existing.end(),
            std::inserter(added, added.begin()));

    // Determine the set of devices removed (only useful once inventory updates are processed)
    std::set<unsigned int> removed;
    std::set_difference(
            existing.begin(), existing.end(),
            current.begin(), current.end(),
            std::inserter(removed, removed.begin()));

    // Determine the set of retained devices, i.e. present in the current and previous inventory
    std::set<unsigned int> retained;
    std::set_intersection(
            existing.begin(), existing.end(),
            current.begin(), current.end(),
            std::inserter(retained, retained.begin()));

    // Remove devices no longer present
    std::set<std::shared_ptr<DeviceImpl>> reportRemoved;
    for (unsigned int id : removed)
    {
        auto i = m_devices.find(id);
        assert(i != m_devices.end());
        reportRemoved.insert(i->second);
        m_mapDevices.erase(i->second->GetBackedDevice().get());
        m_devices.erase(i);
    }

    // Add new devices
    std::set<std::shared_ptr<DeviceImpl>> reportAdded;
    for (unsigned int id : added)
    {
        auto i = devices.find(id);
        assert(i != devices.end());
        auto dev = std::make_shared<DeviceImpl>(*this, i->second);
        m_devices.insert(std::make_pair(id, dev));
        m_mapDevices.insert(std::make_pair(i->second.get(), dev.get()));
        reportAdded.insert(dev);
    }

    // Update existing devices
    for (unsigned int id : retained)
    {
        auto i = m_devices.find(id);
        assert(i != m_devices.end());

        auto j = devices.find(id);
        assert(j != devices.end());

        m_mapDevices.erase(i->second->GetBackedDevice().get());
        m_mapDevices.insert(std::make_pair(j->second.get(), i->second.get()));

        i->second->Update(j->second);

    }

    Delegate &delegate = m_delegate;
    for (const std::shared_ptr<DeviceImpl> &dev : reportAdded)
    {
        m_mainThread.Queue(
            [dev, &delegate]() mutable
            {
                delegate.OnDeviceAdded(dev);
            });
    }

    for (const std::shared_ptr<DeviceImpl> &dev : reportRemoved)
    {
        m_mainThread.Queue(
            [dev, &delegate]() mutable
            {
                delegate.OnDeviceRemoved(dev);
            });
    }
}


void Handler::SendZCLCommand(FacilitydInterface::Application &app,
        uint16_t cluster, uint8_t cmd, CPacket &payload)
{
    std::shared_ptr<CMobileProtocolProcessor> pp(m_pService->m_processor);
    if (!pp)
        return;

    auto ba = app.GetBackedApplication();
    unsigned int id = ba->m_device.m_nIdentifier;
    uint8_t endpoint = ba->m_nEndpoint;
    unsigned int gateway = ba->m_device.m_network.m_gateway.m_nIdentifier;
    unsigned int adapter = ba->m_device.m_network.m_nIdentifier;

    // TODO frame sequence is currently fixed to 0
    uint8_t header[] = { 0x11, 0, cmd };

    CPacket asdu(&header, sizeof(header), payload.GetSizeEx());
    if (!payload.IsEmpty())
        asdu.Append(payload);

    pp->DataRequest(id, endpoint, cluster, asdu,
            [](unsigned int nStatus, std::shared_ptr<CMobileProtocolProcessor> instance)
            {
            }, gateway, adapter);
}


void Handler::OnAttributeChanged(CFacilityZigBeeAttribute &attribute)
{
    auto guard = shared_from_this();

    auto pa = std::make_shared<CFacilityZigBeeAttribute>(std::move(attribute));
    m_mainThread.Queue(
            [pa, this, guard]() mutable
            {
                CFacilityZigBeeAttribute &attribute = *pa;
                auto i = m_mapDevices.find(&attribute.m_cluster.m_application.m_device);
                if (i == m_mapDevices.end())
                {
                    OIC_LOG_V(WARNING, TAG, "Attribute change notification for unmapped device");
                    return;
                }

                i->second->OnAttributeChanged(attribute);
            });
}


} // end of anonymous namespace


////////////////////////////////////////////////////////////////////////
// FacilitydInterface::Impl

class FacilitydInterface::Impl
{
    public:
        Impl(const Options &opts, Delegate &d, ThreadDispatcher &mainThread)
        : m_delegate(d),
          m_options(opts),
          m_mainThread(mainThread),
          m_asyncTerminate([this](ev::Async &){ m_cbAsyncTerminate(); }),
          m_thread(&Impl::loop, this)
        {
        }

        ~Impl()
        {
            m_asyncTerminate.Signal();
            m_thread.join();
        }

    private:
        // Event loop, executed on a dedicated thread
        void loop();

    private:
        Delegate &m_delegate;

        ev::Async m_asyncTerminate;
        const Options m_options;
        ThreadDispatcher &m_mainThread;

        std::thread m_thread;
        std::function<void()> m_cbAsyncTerminate; // Needs synchronization
};


////////////////////////////////////////////////////////////////////////
// ThreadDispatcher

ThreadDispatcher::~ThreadDispatcher() = default;


////////////////////////////////////////////////////////////////////////
// FacilitydInterface::Application::RegistrationCookie

FacilitydInterface::Application::RegistrationCookie::~RegistrationCookie() = default;


////////////////////////////////////////////////////////////////////////
// FacilitydInterface

FacilitydInterface::FacilitydInterface(const Options &opts, Delegate &d, ThreadDispatcher &mainThread)
: m_pImpl(new Impl(opts, d, mainThread))
{
}


FacilitydInterface::~FacilitydInterface() = default;


void FacilitydInterface::Impl::loop()
{
    LoadAvailableFacilities();

    ev::EventLoop loop;
    m_cbAsyncTerminate =
            [&loop](){
                loop.breakLoop();
            };

    std::shared_ptr<Handler> pHandler = std::make_shared<Handler>(loop, m_options, m_delegate, m_mainThread);
    pHandler->TriggerConnect();

    m_asyncTerminate.start(loop);

    OIC_LOG(INFO, TAG, "Event loop running");
    loop.run();
    OIC_LOG(INFO, TAG, "Event loop terminated");
    m_asyncTerminate.stop();
}


////////////////////////////////////////////////////////////////////////
// Stubs for libfacility

void CFacilityZone::OnAttributeChanged(CFacilityZigBeeAttribute &attribute)
{
}

void CFacilityService::OnAttributeChanged(CFacilityZigBeeAttribute &attribute)
{
}
