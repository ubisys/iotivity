// DeviceInformation.cpp : implementation file
//
// Copyright(C) 2016 ubisys technologies GmbH, Duesseldorf, Germany.
// All rights reserved.
//
// www.ubisys.de
// support@ubisys.de
//
// Creates an XML file containing device information. These are stubs only,
// which need to be implemented for the target platform

#include <cstdlib>
#include <string>
#include <vector>
#include <mutex>
#include <list>
#include <map>
#include "CompactFramework.h"
#include "CompactXML.h"
#include "CompactBase64.h"
#include "CompactBase64Ex.h"
#include "DeviceInformation.h"

/////////////////////////////////////////////////////////////////////////////
// Machine and client instance information glue

bool RetrieveMachineInformation(std::string &strMachine)
{
	strMachine = "Native C++ Machine";

	return true;
}


bool RetrieveLocaleInformation(std::string &strLocale)
{
	strLocale = "en-us";

	return true;
}


bool RetrieveDeviceInformation(std::string &strDeviceID, std::string &strDeviceName,
	std::string &strModel, std::string &strMachine, std::string &strSystemName,
	std::string &strSystemVersion, std::string &strLocale)
{
	// The device ID is a UUID for a specific client instance. A random ID
	// is acceptable if it is stored persistently. Systems like iOS already
	// provide APIs to obtain such an ID, for example

	strDeviceID = "310e7367-892d-44ac-ad37-af563b51f16a";
	strDeviceName = "ubisys iotivity plugin";
	strModel = "None";
	strSystemName = "Linux";
	strSystemVersion = "";

	return RetrieveMachineInformation(strMachine) && RetrieveLocaleInformation(strLocale);
}


bool RetrieveOperatingSystemVersion(uint32_t &nVersion)
{
	nVersion = 0x00031400;

	return true;
}


bool RetrieveAppVersion(std::string &strVersion)
{
	strVersion = "1.0.0";

	return true;
}


CCompactXMLNode *AppendKeyAndValue(CCompactXMLDocument &document, CCompactXMLNode &node,
	const CCompactXMLString::value_type *const pszKey,
	const CCompactXMLString::value_type *const pszValue)
{
	CCompactXMLNode *pNode = node.AppendChild(document.CreateElement(pszKey));
	pNode->AppendChild(document.CreateTextNode(pszValue));

	return pNode;
}


CCompactXMLElement *AppendDeviceInformation(CCompactXMLDocument &document,
	CCompactXMLElement *pParent)
{
	std::string strDeviceID, strDeviceName, strModel, strMachine,
		strSystemName, strSystemVersion, strLocale, strAppVersion;

	// Collect device information
	VERIFY(RetrieveDeviceInformation(strDeviceID, strDeviceName, strModel,
		strMachine, strSystemName, strSystemVersion, strLocale));

	// Add app version information
	VERIFY(RetrieveAppVersion(strAppVersion));

	CCompactXMLNode *pRoot = pParent ?
		pParent->AppendChild(document.CreateElement(_CXMLT("device"))) :
		document.AppendChild(document.CreateElement(_CXMLT("device")));

	AppendKeyAndValue(document, *pRoot, _CXMLT("vendor"), _CXMLT("ubisys"));
	AppendKeyAndValue(document, *pRoot, _CXMLT("model"), strModel.c_str());
	AppendKeyAndValue(document, *pRoot, _CXMLT("machine"), strMachine.c_str());
	AppendKeyAndValue(document, *pRoot, _CXMLT("locale"), strLocale.c_str());

	CCompactXMLNode *pSystem =
		pRoot->AppendChild(document.CreateElement(_CXMLT("system")));

	AppendKeyAndValue(document, *pSystem, _CXMLT("name"), strSystemName.c_str());
	AppendKeyAndValue(document, *pSystem, _CXMLT("version"), strSystemVersion.c_str());

	CCompactXMLNode *pApp =
		pRoot->AppendChild(document.CreateElement(_CXMLT("app")));

	AppendKeyAndValue(document, *pApp, _CXMLT("version"), strAppVersion.c_str());

	AppendKeyAndValue(document, *pRoot, _CXMLT("id"), strDeviceID.c_str());

	CCompactXMLNode *pNode = pRoot->AppendChild(document.CreateElement(_CXMLT("name")));
	pNode->AppendChild(document.CreateCDATASection(strDeviceName.c_str()));

	return static_cast<CCompactXMLElement *>(pRoot);
}


void CreateDeviceInformation(CCompactXMLDocument &document)
{
	// Create XML prolog: <?xml version="1.0" encoding="utf-8" ?>
	document.AppendChild(document.CreateProcessingInstruction(_CXMLT("xml"),
		_CXMLT("version=\"1.0\" encoding=\"utf-8\"")));

	AppendDeviceInformation(document);
}

