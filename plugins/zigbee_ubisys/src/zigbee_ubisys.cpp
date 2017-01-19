// zigbee_ubisys.cpp
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
 * Plugin to interface to the ubisys Facility service
 */

#define __STDC_FORMAT_MACROS
#include <cinttypes>
#include <cfloat>
#include <cstdbool>
#include <cstring>
#include <cstdlib>
#include <cassert>
#include <cmath>
#include <cerrno>
#include <memory>
#include <map>
#include <queue>
#include <mutex>
#include <set>
#include <list>
#include <functional>
#include <string>
#include <sstream>
#include <iomanip>

#include "zigbee_ubisys.h"
#include "pluginlist.h"

#include "ocpayload.h"
#include "oic_malloc.h"
#include "oic_string.h"
#include "logger.h"

#include <sys/time.h>
#include <sys/select.h>

#include "FacilityServiceInterface.h"

#include <CompactFramework.h>
#include <CompactXML.h>
#include <Packet.h>
#include <IEEE802154CommonTypes.h>
#include <ZigBeeCommonTypes.h>
#include <ZigBeeAttribute.h>
#include <ZigBeeAttributeEx.h>
#include <ServiceAsset.h>
#include <FacilityService.h>


using namespace std::placeholders;


#define TAG "zigbeeUbisys"


////////////////////////////////////////////////////////////////////////
// OIC resource types

static const char* OIC_BINARY_SWITCH =  "oic.r.switch.binary";
static const char* OIC_MOTION_SENSOR =  "oic.r.sensor.motion";
static const char* OIC_WATER_SENSOR =   "oic.r.sensor.water";
static const char* OIC_FIRE_SENSOR =    "oic.r.sensor.fire";
static const char* OIC_CONTACT_SENSOR = "oic.r.sensor.contact";


////////////////////////////////////////////////////////////////////////
// Forward declarations

static OCEntityHandlerResult ProcessEHRequest(PIPluginBase * plugin,
    OCEntityHandlerRequest *ehRequest, OCRepPayload **payload);

namespace {
    class ResourceMapping;
}


////////////////////////////////////////////////////////////////////////
// PIPlugin_ZigbeeUbisys_Private
// private plugin data

class PIPlugin_ZigbeeUbisys_Private final
: private FacilityServiceInterface::Delegate,
  private ThreadDispatcher
{
    public:
        PIPlugin_ZigbeeUbisys_Private(PIPlugin_ZigbeeUbisys *plugin,
                const FacilityServiceInterface::Options &options)
        : m_plugin(plugin),
          m_facility(options, *this, *this)
        {
        }

    // Overrides: FacilityServiceInterface::Delegate
    public:
        void OnDeviceAdded(const std::shared_ptr<FacilityServiceInterface::Device> &) override;
        void OnDeviceRemoved(const std::shared_ptr<FacilityServiceInterface::Device> &) override;

    // Overrides: ThreadDispatcher
    public:
        void Queue(const std::function<void()> &cb) override
        {
            QueueForMainThread(cb);
        }

    public:
        // Queue a function to be executed on the main thread (to be invoked on any thread)
        void QueueForMainThread(const std::function<void()> &cb);

        // Execute any pending, queued jobs (to be invoked on the main thread)
        void RunQueuedJobs();

    public:
        // Pointer to the plugin data
        PIPlugin_ZigbeeUbisys *const m_plugin;

    private:
        // The interface class to the facility service
        FacilityServiceInterface m_facility;

        // Queue of jobs (functions) to execute on the main thread and the associated mutex
        std::mutex m_mutex;
        std::queue<std::function<void()>> m_jobqueue;
};


////////////////////////////////////////////////////////////////////////
// PIResource_ZigbeeUbisys_Private
// Private, per-resource data

struct PIResource_ZigbeeUbisys_Private
{
    std::unique_ptr<ResourceMapping> m_pMapping;

    PIResource_ZigbeeUbisys_Private(std::unique_ptr<ResourceMapping> &&m)
    : m_pMapping(std::move(m))
    {
    }
};


namespace { // anonymous namespace


////////////////////////////////////////////////////////////////////////
// Value
// Encapsulation of a generic value

class Value
{
    public:
        enum class Type {
            Null,
            Int,
            Double,
            Bool,
            String,
            ByteString,
            Object,
            Array
        };

    public:
        virtual ~Value();
        virtual Type GetType() const = 0;
};


Value::~Value() = default;


////////////////////////////////////////////////////////////////////////
// BoolValue
// Value specialization for a bool

class BoolValue
: public Value
{
    public:
        BoolValue(bool bValue)
        : m_bValue(bValue)
        {
        }

    public:
        virtual Type GetType() const override
        {
            return Type::Bool;
        }

    public:
        bool Get() const
        {
            return m_bValue;
        }

        void Set(bool bValue)
        {
            m_bValue = bValue;
        }

    private:
        bool m_bValue;
};


////////////////////////////////////////////////////////////////////////
// IntValue
// Value specialization for an int

class IntValue
: public Value
{
    public:
        IntValue(int64_t v)
        : m_nValue(v)
        {
        }

    public:
        virtual Type GetType() const override
        {
            return Type::Int;
        }

    public:
        int64_t Get() const
        {
            return m_nValue;
        }

        void Set(int64_t v)
        {
            m_nValue = v;
        }

    private:
        int64_t m_nValue;
};


////////////////////////////////////////////////////////////////////////
// ResourceMapping
// Generic mapping of a ZigBee resource (application cluster) to an
// OCF/iotivity resource

class ResourceMapping
{
    // Type definitions
    public:
        using ValueMap = std::map<std::string, std::unique_ptr<Value>>;

        // Can be thrown from the constructor of derived classes to signal
        // that this specific mapping is not valid, e.g. based on cluster
        // attributes
        class UnsupportedMapping : public std::runtime_error
        {
        public:
            UnsupportedMapping() : std::runtime_error("UnsupportedMapping")
            {
            }
        };

    // Protected constructor. Derived classes to be instantiated via the create() factory
    protected:
        ResourceMapping(PIPlugin_ZigbeeUbisys_Private &priv,
                const std::string &uri,
                const char *pszResourceType);

    // Destructor
    public:
        virtual ~ResourceMapping();

    // Public interface
    public:
        const char* GetResourceType();


        // Create an instance of a ResourceMapping for the given cluster
        // (factory function to instantiate specialized, derived classes of ResourceMapping)
        static PIResource_ZigbeeUbisys* create(PIPlugin_ZigbeeUbisys_Private &,
                const std::string &uri,
                const std::shared_ptr<FacilityServiceInterface::Application> &app,
                uint16_t cluster);

    // Overridables / pure virtual functions
    // To be implemented by derived classes
    public:
        virtual ValueMap HandleGet() = 0;
        virtual void HandlePut(const ValueMap &) = 0;

    // Interface for derived classes
    protected:
        // Notify the stack that the resource state has changed
        // This will notify any registered observers
        void OnResourceChanged();

    // Private implementation
    private:
        // Helper function for create()
        // This is the actual factory which creates the instances based on the cluster type
        static std::unique_ptr<ResourceMapping> instantiate(
                PIPlugin_ZigbeeUbisys_Private &pd,
                const std::string &uri,
                const std::shared_ptr<FacilityServiceInterface::Application> &app,
                uint16_t cluster);

        // Helper function for the constructor; creates the PIResource_ZigbeeUbisys instance
        static PIResource_ZigbeeUbisys* createResource(PIPlugin_ZigbeeUbisys_Private &,
                const char *pszResourceType,
                const std::string &uri);

    // Private data
    private:
        // Private plugin data
        PIPlugin_ZigbeeUbisys_Private &m_privData;

        // The OIC resource type, pointer to a static string
        const char *m_pszResourceType;

        // Owned by the stack, once registered
        PIResource_ZigbeeUbisys *m_pResource;
};


////////////////////////////////////////////////////////////////////////
// BinarySwitchMapping

class BinarySwitchMapping : public ResourceMapping
{
    public:
        BinarySwitchMapping(
                PIPlugin_ZigbeeUbisys_Private &p,
                const std::string &uri,
                const std::shared_ptr<FacilityServiceInterface::Application> &app);

    // Overrides: ResourceMapping
    public:
        ValueMap HandleGet() override;
        void HandlePut(const std::map<std::string, std::unique_ptr<Value>> &) override;

    private:
        void OnAttributeChanged(const CFacilityZigBeeAttribute &);

    private:
        std::shared_ptr<FacilityServiceInterface::Application> m_app;
        std::unique_ptr<FacilityServiceInterface::Application::RegistrationCookie> m_cookie;

        bool m_bValue = false;
        bool m_bValueValid = false;
};


BinarySwitchMapping::BinarySwitchMapping(
        PIPlugin_ZigbeeUbisys_Private &p,
        const std::string &uri,
        const std::shared_ptr<FacilityServiceInterface::Application> &app)
: ResourceMapping(p, uri, OIC_BINARY_SWITCH),
  m_app(app),
  m_cookie(m_app->RegisterAttributeListener(6, std::bind(&BinarySwitchMapping::OnAttributeChanged, this, _1)))
{
    // Try to get attribute 0 (OnOff)
    auto &backed = *app->GetBackedApplication();
    auto i = backed.m_inbound.find(6);
    if (i != backed.m_inbound.end())
    {
        std::pair<uint8_t, bool> value;
        i->second->GetAttributeValue(0, value);

        m_bValueValid = value.second;
        m_bValue = (value.first != 0);
    }
    else
    {
        m_bValueValid = false;
        m_bValue = false;
    }
}


BinarySwitchMapping::ValueMap BinarySwitchMapping::HandleGet()
{
   using UV = std::unique_ptr<Value>;
   ValueMap m;

   // If valid, set value
   if (m_bValueValid)
       m["value"] = UV(new BoolValue(m_bValue));

    return m;
}


void BinarySwitchMapping::HandlePut(const std::map<std::string, std::unique_ptr<Value>> &v)
{
    // Check the parameters passed
    auto i = v.find("value");
    if (i == v.end())
    {
        OIC_LOG(WARNING, TAG, "Binary Switch: PUT w/o value");
        return;
    }

    if (i->second->GetType() != Value::Type::Bool)
    {
        OIC_LOG(WARNING, TAG, "Binary Switch: PUT with invalid value");
        return;
    }

    bool value = static_cast<BoolValue &>(*i->second).Get();
    OIC_LOG_V(INFO, TAG, "Binary switch: set to %s", value ? "ON" : "OFF");

    // Send either an On or Off command, depending on the desired state
    CPacket payload;
    m_app->SendZCLCommamnd(6, (value ? 1 : 0), payload);
}


void BinarySwitchMapping::OnAttributeChanged(const CFacilityZigBeeAttribute &attr)
{
    // Only process attribute 0 (OnOff)
    if (attr.m_attribute->m_wAttributeID != 0)
        return;

    // Ensure the type is correct
    if (attr.m_attribute->m_nType != CZigBeeAttribute::typeBoolean)
        return;

    // Get the value
    uint8_t v = *static_cast<const uint8_t *>(attr.m_attribute->GetData());
    bool bValid = (v == 0) || (v == 1);
    bool bValue = (v == 1);

    OIC_LOG_V(INFO, TAG, "BinarySwitch: %s", bValid ? (bValue ? "ON" : "OFF") : "<invalid>");

    // And update the state

    m_bValue = bValue;
    m_bValueValid = bValid;

    OnResourceChanged();
}



////////////////////////////////////////////////////////////////////////
// IASZoneMapping

class IASZoneMapping : public ResourceMapping
{
    public:
        IASZoneMapping(
                PIPlugin_ZigbeeUbisys_Private &p,
                const std::string &uri,
                const std::shared_ptr<FacilityServiceInterface::Application> &app);

    // Overrides: ResourceMapping
    public:
        ValueMap HandleGet() override;
        void HandlePut(const std::map<std::string, std::unique_ptr<Value>> &) override;

    private:
        void OnAttributeChanged(const CFacilityZigBeeAttribute &);
        static const char *mapResourceType(const std::shared_ptr<FacilityServiceInterface::Application> &app);
        static uint16_t getAlarmMask(const std::shared_ptr<FacilityServiceInterface::Application> &app);

    private:
        std::shared_ptr<FacilityServiceInterface::Application> m_app;
        std::unique_ptr<FacilityServiceInterface::Application::RegistrationCookie> m_cookie;

        // Indicates which bits to evaluate of the ZoneStatus attribute
        uint16_t m_nAlarmMask;

        bool m_bValue = false;
        bool m_bValueValid = false;
};


IASZoneMapping::IASZoneMapping(
        PIPlugin_ZigbeeUbisys_Private &p,
        const std::string &uri,
        const std::shared_ptr<FacilityServiceInterface::Application> &app)
: ResourceMapping(p, uri, mapResourceType(app)),
  m_app(app),
  m_cookie(m_app->RegisterAttributeListener(0x500, std::bind(&IASZoneMapping::OnAttributeChanged, this, _1))),
  m_nAlarmMask(getAlarmMask(app))
{
    // Try to get attribute 2 (Zone status)
    auto &backed = *app->GetBackedApplication();
    auto i = backed.m_inbound.find(6);
    if (i != backed.m_inbound.end())
    {
        std::pair<uint16_t, bool> value;
        i->second->GetAttributeValue(2, value);

        m_bValueValid = value.second;
        m_bValue = (value.first & m_nAlarmMask);
    }
    else
    {
        m_bValueValid = false;
        m_bValue = false;
    }
}


ResourceMapping::ValueMap IASZoneMapping::HandleGet()
{
    ValueMap m;

    if (m_bValueValid)
        m["value"] = std::unique_ptr<Value>(new BoolValue(m_bValue));

    return m;
}


void IASZoneMapping::HandlePut(const std::map<std::string, std::unique_ptr<Value>> &)
{
    // TODO fail (readonly, not permitted)
}


void IASZoneMapping::OnAttributeChanged(const CFacilityZigBeeAttribute &attr)
{
    if (!attr.m_attribute)
        return;

    CZigBeeAttribute &za = *attr.m_attribute;

    // Only interested in attribute 2: Zone Status
    if (za.m_wAttributeID != 2)
        return;

    // Check the type
    if (za.m_nType != CZigBeeAttribute::typeBitmap16)
        return;

    uint16_t value = *static_cast<const uint16_t *>(za.m_pStorage);

    OIC_LOG_V(INFO, TAG, "IAS Zone status update: %04x", value);

    m_bValue = value & m_nAlarmMask;
    m_bValueValid = true;

    OnResourceChanged();
}


const char*
IASZoneMapping::mapResourceType( const std::shared_ptr<FacilityServiceInterface::Application> &app)
{
    std::shared_ptr<CFacilityZigBeeApplication> bapp = app->GetBackedApplication();
    auto i = bapp->m_inbound.find(0x500);
    assert(i != bapp->m_inbound.end());
    auto iasCluster = i->second;

    std::pair<uint16_t, bool> zoneType;
    iasCluster->GetAttributeValue(0x0001, zoneType);

    if (!zoneType.second) // TODO recovery needed on inventory update
        throw UnsupportedMapping();

    switch (zoneType.first)
    {
        case 0x000d: return OIC_MOTION_SENSOR;
        case 0x0015: return OIC_CONTACT_SENSOR;
        case 0x0028: return OIC_FIRE_SENSOR;
        case 0x002a: return OIC_WATER_SENSOR;

        default:
            throw UnsupportedMapping();
    }
}

uint16_t IASZoneMapping::getAlarmMask(const std::shared_ptr<FacilityServiceInterface::Application> &app)
{
    std::shared_ptr<CFacilityZigBeeApplication> bapp = app->GetBackedApplication();
    auto i = bapp->m_inbound.find(0x500);
    assert(i != bapp->m_inbound.end());
    auto iasCluster = i->second;

    std::pair<uint16_t, bool> zoneType;
    iasCluster->GetAttributeValue(0x0001, zoneType);

    if (!zoneType.second) // TODO recovery needed on inventory update
        throw UnsupportedMapping();

    switch (zoneType.first)
    {
        case 0x000d: return 2; // motion: Alarm2
        case 0x0015: return 1; // contact: Alarm1
        case 0x0028: return 1; // fire: Alarm1
        case 0x002a: return 1; // water: Alarm1

        default:
            throw UnsupportedMapping();
    }
}


////////////////////////////////////////////////////////////////////////
// ResourceMapping

ResourceMapping::ResourceMapping(PIPlugin_ZigbeeUbisys_Private &priv,
        const std::string &uri, const char *pszResourceType)
: m_privData(priv),
  m_pszResourceType(pszResourceType),
  m_pResource(createResource(priv, pszResourceType, uri))
{
    if (!m_pResource)
        throw std::bad_alloc();
}


ResourceMapping::~ResourceMapping() = default;


const char* ResourceMapping::GetResourceType()
{
    return m_pszResourceType;
}


PIResource_ZigbeeUbisys* ResourceMapping::create(
        PIPlugin_ZigbeeUbisys_Private &pd,
        const std::string &uri,
        const std::shared_ptr<FacilityServiceInterface::Application> &app,
        uint16_t cluster)
{
    // Try to instantiate the mapping
    std::unique_ptr<ResourceMapping> m;
    try {
        m = instantiate(pd, uri, app, cluster);
    }
    catch (const UnsupportedMapping &)
    {
        return 0;
    }

    if (!m)
        return 0;

    // And setup private resource data to point to the ResourceMapping
    auto res = m->m_pResource;
    res->priv = new PIResource_ZigbeeUbisys_Private(std::move(m));

    return res;
}


std::unique_ptr<ResourceMapping> ResourceMapping::instantiate(
        PIPlugin_ZigbeeUbisys_Private &pd,
        const std::string &uri,
        const std::shared_ptr<FacilityServiceInterface::Application> &app,
        uint16_t cluster)
{
    using UR = std::unique_ptr<ResourceMapping>;

    switch (cluster)
    {
        // OnOff cluster
        case 6:
            return UR(new BinarySwitchMapping(pd, uri, app));

        // IAS Zone
        case 0x500:
            return UR(new IASZoneMapping(pd, uri, app));

        default:
            return 0;
    }
}


PIResource_ZigbeeUbisys* ResourceMapping::createResource(PIPlugin_ZigbeeUbisys_Private &privData,
        const char *pszResourceType, const std::string &uri)
{
    // Allocate the PIResource_ZigbeeUbisys and populate the header (base class members)
    PIResource_ZigbeeUbisys *piResource = (PIResource_ZigbeeUbisys *) OICMalloc(sizeof(*piResource));
    if (!piResource)
    {
       OIC_LOG(ERROR, TAG, "Out of memory");
       return 0;
    }

    piResource->header.plugin = (PIPluginBase *)privData.m_plugin;

    // TODO OOM
    piResource->header.piResource.uri = static_cast<char *>(OICCalloc(1, uri.size() + 1));
    memcpy(piResource->header.piResource.uri, uri.data(), uri.size() + 1);

    piResource->header.piResource.resourceTypeName = pszResourceType;
    piResource->header.piResource.resourceInterfaceName = OC_RSRVD_INTERFACE_DEFAULT;

    piResource->header.piResource.callbackParam = NULL;
    piResource->header.piResource.resourceProperties = 0;

    return piResource;
}


void ResourceMapping::OnResourceChanged()
{
    // Notify the stack on the resource update
    m_privData.m_plugin->header.ObserveNotificationUpdate(
            &m_privData.m_plugin->header,
            m_pResource->header.piResource.resourceHandle);
}

} // end of anonymous namespace


////////////////////////////////////////////////////////////////////////
// PIPlugin_ZigbeeUbisys_Private

void PIPlugin_ZigbeeUbisys_Private::QueueForMainThread(const std::function<void()> &cb)
{
    std::lock_guard<std::mutex> lg(m_mutex);
    m_jobqueue.push(cb);
}


void PIPlugin_ZigbeeUbisys_Private::RunQueuedJobs()
{
    // Execute any jobs in the queue
    std::queue<std::function<void()>> q;

    // First, acquire the mutex and retrieve the queue contents
    {
        std::lock_guard<std::mutex> lg(m_mutex);
        std::swap(q, m_jobqueue);
    }

    // Then process the queue contents without holding the mutex acquired
    while (!q.empty())
    {
        q.front()();
        q.pop();
    }
}


void PIPlugin_ZigbeeUbisys_Private::OnDeviceAdded(const std::shared_ptr<FacilityServiceInterface::Device> &dev)
{
    uint64_t addr64 = dev->GetBackedDevice()->m_address.m_qwExtended;
    OIC_LOG_V(INFO, TAG, "Add resources for %016" PRIx64, addr64);

    // Iterate over all applications
    auto apps = dev->GetApplications();
    for (const auto &p : apps)
    {
        uint8_t ep = p.first;
        const std::shared_ptr<FacilityServiceInterface::Application> &app = p.second;

        OIC_LOG_V(INFO, TAG, "Endpoint %u", ep);

        // And over all clusters
        std::set<uint16_t> clusters = app->GetInboundClusters();
        for (uint16_t cluster : clusters)
        {
            OIC_LOG_V(INFO, TAG, "Cluster %04x", cluster);

            // Create the URI
            std::ostringstream oss;
            oss << std::setfill('0');
            oss << PI_ZIGBEE_PREFIX << '/';
            oss << std::hex << std::setw(16) << addr64;
            oss << '/' << std::dec << +ep;
            oss << '/' << std::hex << std::setw(4) << cluster;

            const std::string &uri = oss.str();

            // And try to instantiate a mapping (if the cluster is supported)
            PIResource_ZigbeeUbisys *r = ResourceMapping::create(*this, uri, app, cluster);

            if (!r)
                continue;

            OIC_LOG_V(INFO, TAG, "got mapping for cluster %04x", cluster);

            // Register the resource within the stack
            m_plugin->header.NewResourceFoundCB(&m_plugin->header, &r->header);
        }
    }
}


void PIPlugin_ZigbeeUbisys_Private::OnDeviceRemoved(const std::shared_ptr<FacilityServiceInterface::Device> &)
{
    // Not implemented yet
}


////////////////////////////////////////////////////////////////////////
// utility functions


// Parses the request payload into a map of attributes/values
static std::map<std::string, std::unique_ptr<Value>> parsePayload(OCRepPayload *payload)
{
    using UV = std::unique_ptr<Value>;

    std::map<std::string, std::unique_ptr<Value>> m;

    for (OCRepPayloadValue *v = payload->values; v; v = v->next)
    {
        UV val;
        switch (v->type)
        {
            case OCREP_PROP_BOOL:
                val = UV(new BoolValue(v->b));
                break;

            case OCREP_PROP_INT:
                val = UV(new IntValue(v->i));
                break;

            default:
                break;
        }

        if (val)
            m[v->name] = std::move(val);
    }

    return m;
}

// Creates a response payload, including the specified attributes/values
static OCRepPayload* createPayload(std::map<std::string, std::unique_ptr<Value>> &m)
{
    OCRepPayload *payload = OCRepPayloadCreate();

    for (const auto &p : m)
    {
        switch (p.second->GetType())
        {
            case Value::Type::Bool:
            {
                OCRepPayloadSetPropBool(payload, p.first.c_str(),
                        static_cast<BoolValue &>(*p.second).Get());
            }
            break;

            case Value::Type::Int:
            {
                OCRepPayloadSetPropInt(payload, p.first.c_str(),
                        static_cast<IntValue &>(*p.second).Get());
            }
            break;

            default:
                OIC_LOG_V(WARNING, TAG, "Payload: unsupported property type %u",
                        static_cast<unsigned int>(p.second->GetType()));
                break;
        }
    }

    return payload;
}


////////////////////////////////////////////////////////////////////////
// Plugin functions

OCStackResult ZigbeeUbisysInit(const char *args, PIPlugin_ZigbeeUbisys ** plugin,
                         PINewResourceFound newResourceCB,
                         PIObserveNotificationUpdate observeNotificationUpdate)
{
    OIC_LOG(INFO, TAG, "ZigbeeUbisysInit");

    if (!plugin)
    {
        return OC_STACK_INVALID_PARAM;
    }

    PIPlugin_ZigbeeUbisys *p = (PIPlugin_ZigbeeUbisys *) OICMalloc(sizeof(PIPlugin_ZigbeeUbisys));

    *plugin = p;
    if (!p)
    {
        return OC_STACK_NO_MEMORY;
    }

    p->header.type = PLUGIN_ZIGBEE_UBISYS;
    p->header.comPort = 0;
    p->header.NewResourceFoundCB = newResourceCB;
    p->header.ObserveNotificationUpdate = observeNotificationUpdate;
    p->header.next = 0;
    p->header.resourceList = 0;
    p->header.processEHRequest = ProcessEHRequest;

    // Parse args:
    // Either simply a hostname or a hostname:port combination

    FacilityServiceInterface::Options options;
    options.m_nPort = 8888;

    const char *pos = strchr(args, ':');
    if (pos)
    {
        options.m_host = std::string(args, pos - args);
        const char *port = pos+1;

        char *endptr;
        unsigned long v = strtoul(port, &endptr, 10);
        if (*endptr || (v > 0xffff))
        {
            OIC_LOG_V(ERROR, TAG, "Invalid port");
            return OC_STACK_ERROR;
        }

        options.m_nPort = v;
    }
    else
    {
        options.m_host = args;
    }

    p->priv = new PIPlugin_ZigbeeUbisys_Private(p, options);

    return OC_STACK_OK;
}

OCStackResult ZigbeeUbisysStop(PIPlugin_ZigbeeUbisys * plugin)
{
	delete plugin->priv;
	OICFree(plugin);

	return OC_STACK_OK;
}

OCStackResult ZigbeeUbisysProcess(PIPlugin_ZigbeeUbisys * plugin)
{
    auto &priv = *plugin->priv;

    priv.RunQueuedJobs();

    // Sleep for 20ms to avoid busy-looping
    // There seems to be no provision witin the plugin infrastructure to monitor file descriptors
    // TODO rather monitor a pipe to get an instant response for queued jobs
    // (but keep the timeout)
    struct timeval tv = { 0, 20000 };
    select(0, 0, 0, 0, &tv);

	return OC_STACK_OK;
}


void ZigBeeUbisysDeleteResourcePriv(PIResource_ZigbeeUbisys_Private *r)
{
    delete r;
}


// The entity handler, invoked via the plugin_wrapper
static OCEntityHandlerResult ProcessEHRequest(PIPluginBase * plugin,
    OCEntityHandlerRequest *ehRequest, OCRepPayload **payload)
{
    if (!ehRequest || !payload)
    {
        return OC_EH_ERROR;
    }

    OCStackResult stackResult = OC_STACK_OK;
    PIResource_ZigbeeUbisys* piResource = 0;
    stackResult = GetResourceFromHandle(plugin, (PIResource**) (&piResource),
                        (OCResourceHandle *)ehRequest->resource);

    if (stackResult != OC_STACK_OK)
    {
        OIC_LOG(ERROR, TAG, "Failed to get resource from handle");
        return OC_EH_ERROR;
    }

    ResourceMapping &m = *piResource->priv->m_pMapping;

    switch (ehRequest->method)
    {
        case OC_REST_GET:
            {
                auto newValues = m.HandleGet();
                *payload = createPayload(newValues);
            }
            break;

        case OC_REST_PUT:
            {
                auto values = parsePayload(*payload);
                m.HandlePut(values);

                // Use the supplied values to update the current set of values
                // This is necessary to reflect the correct (desired) state, due to the
                // actual update happening asynchronously.
                auto newValues = m.HandleGet();
                for (auto &p : values)
                    newValues[p.first] = std::move(p.second);

                *payload = createPayload(newValues);
            }
            break;

        default:
            return OC_EH_FORBIDDEN;
    }

    return OC_EH_OK;
}
