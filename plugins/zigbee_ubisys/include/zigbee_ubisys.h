// zigbee_ubisys.h
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

#include "plugintranslatortypes.h"


#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initializes the ubisys ZigBee / facilityd interface plugin
 *
 * @param[in]  args   Plugin arguments: hostname or hostname:port of the facility service
 *
 * @param[out] plugin A pointer to the plugin structureNa
 *
 * @param[in] newResourceCB A function pointer to the callback that will be
 *                          invoked when a ZigBee cluster is found that matches
 *                          a valid OIC resource.
 *
 * @param[in] observeNotificationUpdate A function pointer to the callback that will be
 *                                      invoked when a mapped resource is updated (i.e. ZigBee
 *                                      attribute report received via facilityd/libfacility)
 */
OCStackResult ZigbeeUbisysInit(const char *args, PIPlugin_ZigbeeUbisys ** plugin,
                         PINewResourceFound newResourceCB,
                         PIObserveNotificationUpdate observeNotificationUpdate);

/**
 * Stop and destroy the plugin
 *
 * @param[in] plugin   pointer to the plugin instance
 */
OCStackResult ZigbeeUbisysStop(PIPlugin_ZigbeeUbisys * plugin);


/**
 * Invoked by the plugin wrapper
 *
 * @param[in] plugin   pointer to the plugin instance
 */
OCStackResult ZigbeeUbisysProcess(PIPlugin_ZigbeeUbisys * plugin);


/**
 * Destructor for the plugin-private data
 *
 * @param[in] pdata   pointer to the private data
 */
void ZigBeeUbisysDeleteResourcePriv(struct PIResource_ZigbeeUbisys_Private *pdata);

#ifdef __cplusplus
}
#endif
