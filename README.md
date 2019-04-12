# ubisys® Smart Facility™ Adapter for IoTivity

Copyright© 2016 ubisys technologies GmbH, Düsseldorf, Germany. All rights reserved.

This project has been sponsored jointly by ubisys technologies GmbH and Qorvo, Inc.
and is licensed under the Apache License, Version 2.0; You may obtain a copy of the
license at <http://www.apache.org/licenses/LICENSE-2.0>.

## Overview
Project "Morpheus" provides a piece of software that acts as an adapter between the 
ubisys Smart Facility Service and the Open Connectivity Foundation's IoTivity project,
connecting the world's first certified ZigBee 3.0 gateway platform to IoTivity. As a
result, it does not only bridge conventional ZigBee products like relays, dimmers, 
smart plugs, and light bulbs to OIC, but it does also fully support energy-harvesting
ZigBee Green Power devices - another world's first.

### Intended Usage
The Smart Facility Adapter for IoTivity is compatible with all gateways and home hubs
running the ubisys Smart Facility Service, including the ubisys ZigBee Gateway G1,
the Qorvo ZigBee 3.0 Gateway reference design based on the GP712, and custom hardware
platforms incorporating the ubisys core ZigBee gateway services.

Typically, the adapter would run on the gateway platform itself and connect to the
local Smart Facility instance, but it can also connect to a remote facility service
over an IPv4 or IPv6 connection.

### Supported Device Types
Following mappings between ZigBee features and OIC models are supported:

- OIC Binary Switch ("oic.r.switch.binary") <-> ZigBee On/Off Cluster (0x0006)
- OIC Water Sensor ("oic.r.sensor.water") <-> ZigBee IAS Zone Cluster (0x0500), "Water Sensor" (ZoneType 0x002A)
- OIC Contact Sensor ("oic.r.sensor.contact") <-> ZigBee IAS Zone Cluster (0x0500), "Contact Switch" (ZoneType 0x0015)
- OIC Motion Sensor ("oic.r.sensor.motion") <-> ZigBee IAS Zone Cluster (0x0500), "Motion Sensor" (ZoneType 0x000D)
- OIC Fire Sensor ("oic.r.sensor.fire") <-> ZigBee IAS Zone Cluster (0x0500), "Fire Sensor" (Zone Type 0x0028)

## Implementation details, build instructions and requirements
The project hosted at https://github.com/ubisys/iotivity is a fork of the official
IoTivity 1.2 release, available at https://github.com/iotivity/iotivity. The changes
made by ubisys affect IotivityandZigBeeServer, such that it utilizes the new ubisys
ZigBee 3.0 plug-in for IoTivity, which is a drop-in replacement for zigbee_wrapper.
For testing, you could use IotivityandZigBeeClient, which remained unmodified.

Notice that unit tests for the ubisys ZigBee plugin are currently not supported and
attempting to build them would fail. It is recommended to just build the server and
client, as described below.

This project heavily relies on the ubisys Smart Facility Service C++ Client SDK, which
is a closed-source library. A C++ 11 compiler is required, e.g. GCC 4.9.3 or above.

### Building
#### 1. Make sure open-source libraries are installed
Following open-source libraries are required and should be installed on your
build system: `libuuid`, `libbsd`, `libev`
They can typically be installed using your distribution's package manager, for
example on an ubuntu 14.04.5 LTS, use the following commands:
```
sudo apt-get install libuuid1 libbsd0 libev4
```
#### 2. Copy dependencies 
Make sure to add `libev++` and `libfacility` for your target platform to the
`/extlibs/ubisys` folder, under the respective subfolders, i.e. `/include` for the
headers and `/local` for building on the local host (currently no cross-builds
supported).
You might also have to add additional external dependencies, as required by
vanilla IoTivity. Then you will be prompted to install specific packages, e.g.
```
git clone https://github.com/01org/tinycbor.git extlibs/tinycbor/tinycbor -b v0.4
```
#### 3. Build the debug version of client and server
Make sure the current working directory is the iotivity top-level directory. Then run
scons. Notice the target string depends on your specific architecture (x86_64 in this
case) and build configuration (debug build in this case):
```
scons out/linux/x86_64/debug/plugins/samples/linux/iotivityandzigbeeserver RELEASE=false
scons out/linux/x86_64/debug/plugins/samples/linux/iotivityandzigbeeclient RELEASE=false
```
#### 4. Build the release version of client and server
Make sure the current working directory is the iotivity top-level directory. Then run
scons. Notice the target string depends on your specific architecture (x86_64 in this
case) and build configuration (release build in this case):
```
scons out/linux/x86_64/release/plugins/samples/linux/iotivityandzigbeeserver
scons out/linux/x86_64/release/plugins/samples/linux/iotivityandzigbeeclient
```
#### Addtional hints for targetting the ARM architecture
Make sure to specify `TARGET_ARCH=arm` and to use `arm` instead of `x86_64` in the 
target path, i.e.
```
scons out/linux/arm/debug/plugins/samples/linux/iotivityandzigbeeserver TARGET_ARCH=arm RELEASE=false
```
#### Trouble-shooting
If you have problems buidling, first try to build vanilla IoTivity on your build
system. Once that works, follow the instructions above to build the ubisys ZigBee
plug-in.
## Commissioning instructions
Currently, the PIN code is hard-coded as "0000", so you need to allow enrollment on
the Facility Service (for ubisys G1 use the web interface, as a platform vendor use
the facility-manage command line tool or your own user interface) with this PIN code,
then connect. After initial enrollment, the credentials are stored permanently.

Start the IotivityandZigbeeServer application (plugins/samples/linux) and provide 
hostname[:port] for the facility service instance on the command line.

## Contact
ubisys technologies GmbH

Neumannstraße 10

40235 Düsseldorf

Phone: +49 (211) 54 21 55 – 00

Fax: +49 (211) 54 21 55 – 99

info@ubisys.de

www.ubisys.de


## Support
For support around this project, please mail support@ubisys.de
