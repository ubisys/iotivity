// EvCompactTimerService.h : header file
//
// Copyright(C) 2016 ubisys technologies GmbH, Duesseldorf, Germany.
// All rights reserved.
//
// www.ubisys.de
// support@ubisys.de
//
// Provides a subset of the CCompactTimerService API on top of libev


#ifndef PLUGINS_ZIGBEE_UBISYS_LIBFACILITY_WRAPPER_INCLUDE_EVCOMPACTTIMERSERVICE_H_
#define PLUGINS_ZIGBEE_UBISYS_LIBFACILITY_WRAPPER_INCLUDE_EVCOMPACTTIMERSERVICE_H_

////////////////////////////////////////////////////////////////////////
// EvCompactTimerService

class EvCompactTimerService
{
	public:
		using time_point = std::chrono::steady_clock::time_point;

	public:
		EvCompactTimerService(ev::EventLoop &loop);
		~EvCompactTimerService();

	public:
		// Creates a new timer. The specified timer callback is executed
		// when the specified timeout has expired. If a reference pointer is provided,
		// once the timer callback has been invoked, the reference is nulled.
		// Until then, the timer might be cancelled. The location of the reference
		// must persist for the lifetime of the timer.
		// This version is for non-static member functions
		void CreateTimer(const unsigned int nTime,
			CCompactTimerClient &client,
			CCompactTimer::MEMBERCALLBACK pfnCallback,
			void *pArgument = 0, CCompactTimer **const ppReference = 0);

		// Creates a new timer. The specified timer callback is executed
		// when the specified timeout has expired. If a reference pointer is provided,
		// once the timer callback has been invoked, the reference is nulled.
		// Until then, the timer might be cancelled. The location of the reference
		// must persist for the lifetime of the timer.
		// This version is for global functions or static member functions
		void CreateTimer(const unsigned int nTime,
			CCompactTimer::STATICCALLBACK pfnCallback, void *pArgument = 0,
			CCompactTimer **const ppReference = 0);

		// Cancels a pending timer. Returns true, if the timer was still
		// pending and canceled, false otherwise
		bool CancelTimer(CCompactTimer *&pTimer);

		static unsigned int CalculateTicks(const unsigned int nMicroseconds);

		const CCompactTimer& GetActiveTimer();

	private:
		class Impl;
		std::unique_ptr<Impl> m_pImpl;
};


#endif /* PLUGINS_ZIGBEE_UBISYS_LIBFACILITY_WRAPPER_INCLUDE_EVCOMPACTTIMERSERVICE_H_ */

