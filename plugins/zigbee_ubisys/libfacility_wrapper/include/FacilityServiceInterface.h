// FacilityServiceInterface.h
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
 */

#ifndef PLUGINS_ZIGBEE_UBISYS_FACILITYSERVICEINTERFACE_H_
#define PLUGINS_ZIGBEE_UBISYS_FACILITYSERVICEINTERFACE_H_


////////////////////////////////////////////////////////////////////////
// Forward declarations

class CFacilityZigBeeDevice;
class CFacilityZigBeeApplication;
class CFacilityZigBeeAttribute;
class CPacket;


////////////////////////////////////////////////////////////////////////
// ThreadDispatcher
// Invoke a function on a different thread
// Generic interface, to be implemented by the application

class ThreadDispatcher
{
    protected:
        ~ThreadDispatcher();

    public:
        virtual void Queue(const std::function<void()> &) = 0;
};


////////////////////////////////////////////////////////////////////////
// FacilityServiceInterface

class FacilityServiceInterface
{
    public:
        // Options
        struct Options
        {
            std::string m_host;
            uint16_t m_nPort;
        };

        class Application;

        // Device wrapper class
        class Device
        {
            public:
                // Returns the current backing device (libfacility)
                // Note that this may change on inventory updates
                virtual std::shared_ptr<CFacilityZigBeeDevice> GetBackedDevice() = 0;

                // Get a map of all known applications
                virtual std::map<uint8_t, std::shared_ptr<Application>> GetApplications() = 0;
        };

        // Application wrapper class
        class Application
        {
            public:
                // Helper cookie for RegisterAttributeListener()
                class RegistrationCookie
                {
                public:
                    virtual ~RegistrationCookie();
                };

                using AttributeChangeCB = std::function<void(const CFacilityZigBeeAttribute &)>;

            public:
                virtual std::shared_ptr<CFacilityZigBeeApplication> GetBackedApplication() = 0;

                virtual std::set<uint16_t> GetInboundClusters() = 0;
                virtual std::set<uint16_t> GetOutboundClusters() = 0;

                // Send a ZCL command
                virtual void SendZCLCommamnd(uint16_t cluster, uint8_t cmd, CPacket &payload) = 0;

                // Register a listener to receive attribute updates for the given cluster
                // Destruction of the returned RegistrationCookie instance will unregister
                // the listener
                virtual std::unique_ptr<RegistrationCookie>
                RegisterAttributeListener(uint16_t cluster, const AttributeChangeCB &) = 0;
        };

        // Delegate; to be implemented by the application
        class Delegate
        {
        public:
            virtual void OnDeviceAdded(const std::shared_ptr<Device> &) = 0;
            virtual void OnDeviceRemoved(const std::shared_ptr<Device> &) = 0;
        };

    public:
        FacilityServiceInterface(const Options &, Delegate &, ThreadDispatcher &mainThread);
        ~FacilityServiceInterface();

    private:
        class Impl;
        std::unique_ptr<Impl> m_pImpl;
};

#endif /* PLUGINS_ZIGBEE_UBISYS_FACILITYSERVICEINTERFACE_H_ */
