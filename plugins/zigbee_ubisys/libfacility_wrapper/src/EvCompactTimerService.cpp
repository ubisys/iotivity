// EvCompactTimerService.cpp : implementation file
//
// Copyright(C) 2016 ubisys technologies GmbH, Duesseldorf, Germany.
// All rights reserved.
//
// www.ubisys.de
// support@ubisys.de
//
// Provides a subset of the CCompactTimerService API on top of libev

#include <list>
#include <map>
#include <set>
#include <cassert>
#include <CompactTimer.h>
#include <libev++.h>
#include "EvCompactTimerService.h"

class EvCompactTimerService::Impl
{
	public:
		Impl(ev::EventLoop &loop);
		~Impl();

	public:
		void CreateTimer(const unsigned int nTime,
				CCompactTimerClient &client,
				CCompactTimer::MEMBERCALLBACK pfnCallback,
				void *pArgument, CCompactTimer **const ppReference);

		void CreateTimer(const unsigned int nTime,
				CCompactTimer::STATICCALLBACK pfnCallback, void *pArgument,
				CCompactTimer **const ppReference);

		bool CancelTimer(CCompactTimer *&pTimer);

		const CCompactTimer& GetActiveTimer();

	private:
		void OnTimeout();
		void Reschedule(time_point now);
		void Dispatch(time_point now);

		void AddTimer(CCompactTimer *);

	private:
		ev::EventLoop &m_loop;

		ev::Timer m_timer;

		CCompactTimer *m_pActiveTimer;

		std::multimap<time_point, CCompactTimer *> m_timersByTime;
		std::map<CCompactTimer *, time_point> m_expiries;
		std::set<CCompactTimer *> m_timers;
};


EvCompactTimerService::Impl::Impl(ev::EventLoop &loop)
: m_loop(loop),
  m_timer(std::bind(&Impl::OnTimeout, this)),
  m_pActiveTimer(0)
{
}


EvCompactTimerService::Impl::~Impl()
{
}


void EvCompactTimerService::Impl::CreateTimer(const unsigned int nTime,
		CCompactTimerClient &client,
		CCompactTimer::MEMBERCALLBACK pfnCallback,
		void *pArgument, CCompactTimer **const ppReference)
{
	// Creates a new timer. The specified timer callback is executed from
	// GreenPeak scheduler context when the specified timeout has expired.
	// If a reference pointer is provided, once the timer callback has been
	// invoked, the reference is nulled. Until then, the timer might be
	// cancelled. The location of the reference must persist for the
	// lifetime of the timer.
	// This version is for non-static member functions

	// Cancellable timer must be null before a new timer is registered
	assert(!ppReference || !*ppReference);

	// Create a new timer object
	CCompactTimer *pTimer = new CCompactTimer(client, pfnCallback,
		pArgument, 0, nTime, ppReference);

	// Add timer to set of pending timers
	AddTimer(pTimer);
}


void EvCompactTimerService::Impl::CreateTimer(const unsigned int nTime,
		CCompactTimer::STATICCALLBACK pfnCallback, void *pArgument,
		CCompactTimer **const ppReference)
{
	// Creates a new timer. The specified timer callback is executed from
	// GreenPeak scheduler context when the specified timeout has expired.
	// If a reference pointer is provided, once the timer callback has been
	// invoked, the reference is nulled. Until then, the timer might be
	// cancelled. The location of the reference must persist for the
	// lifetime of the timer.
	// This version is for global functions or static member functions

	// Cancellable timer must be null before a new timer is registered
	assert(!ppReference || !*ppReference);

	// Create a new timer object
	CCompactTimer *pTimer = new CCompactTimer(pfnCallback, pArgument,
		0, nTime, ppReference);

	// Add timer to set of pending timers
	AddTimer(pTimer);
}


bool EvCompactTimerService::Impl::CancelTimer(CCompactTimer *&pTimer)
{
	auto i = m_timers.find(pTimer);
	if (i == m_timers.end())
		return false;
	m_timers.erase(i);

	auto j = m_expiries.find(pTimer);
	assert(j != m_expiries.end());
	time_point due = j->second;
	m_expiries.erase(j);

	auto r = m_timersByTime.equal_range(due);
	for (auto i = r.first; i != r.second; i++)
	{
		if (i->second == pTimer)
		{
			m_timersByTime.erase(i);
			if (pTimer->m_ppReference)
			    *pTimer->m_ppReference = 0;
			delete pTimer;
			break;
		}
	}

	return true;
}


const CCompactTimer& EvCompactTimerService::Impl::GetActiveTimer()
{
	return *m_pActiveTimer;
}


void EvCompactTimerService::Impl::OnTimeout()
{
	auto now = std::chrono::steady_clock::now();

	Dispatch(now);
	Reschedule(now);
}


void EvCompactTimerService::Impl::Reschedule(time_point now)
{
	m_timer.stop();
	if (m_timersByTime.empty())
		return;

	auto tp = m_timersByTime.begin()->first;
	if (tp <= now)
	{
		// break out of the current context and dispatch on invocation of onTimeot()
		// reschedule() might is called by CreateTimer()
		m_timer.set(0, 0);
	}
	else
	{
		auto diff = tp - now;
		m_timer.set(std::chrono::duration_cast<std::chrono::duration<double>>(diff).count(), 0);
	}

	m_timer.start(m_loop);
}


void EvCompactTimerService::Impl::Dispatch(time_point now)
{
	std::list<CCompactTimer *> timers;

	// Remove all timers expired from the map first
	// and dispatch them at a later stage - this is to allow creating new timers
	// from a callback
	while (!m_timersByTime.empty() && (m_timersByTime.begin()->first <= now))
	{
		 const auto i = m_timersByTime.begin();

		 CCompactTimer *t = i->second;
		 timers.push_back(t);

		 m_timersByTime.erase(i);
		 m_expiries.erase(t);
		 m_timers.erase(t);
	}

	for (auto *pTimer : timers)
	{
		if (pTimer->m_ppReference)
			*pTimer->m_ppReference = 0;

		m_pActiveTimer = pTimer;

		// Invoke the timer callback method. Notice that the callback might
		// cancel existing timers or register new timers
		if (pTimer->m_pClient)
		{
			// Invoke a non-static member function on the client instance,
			// which must be an instance of a CCompactTimerServiceClient
			// derived class
			(pTimer->m_pClient->*pTimer->m_pfnCallback)(pTimer->m_pArgument);
		}
		else
		{
			// Invoke a global function or static member function
			(*pTimer->m_pfnStaticCallback)(pTimer->m_pArgument);
		}

		m_pActiveTimer = 0;

		delete pTimer;
	}
}


void EvCompactTimerService::Impl::AddTimer(CCompactTimer *pTimer)
{
	const auto now = std::chrono::steady_clock::now();
	const auto due = now + std::chrono::microseconds(pTimer->m_nTimeSpan);

	// Determine if a reschedule is required, that is:
	// Either no timers registered yet (no timer scheduled) or this timer expires earlier
	// then the earliest registered timer.
	const bool bReschedule = m_timersByTime.empty() || (m_timersByTime.begin()->first > due);

	m_timers.insert(pTimer);
	m_expiries.insert(std::make_pair(pTimer, due));
	m_timersByTime.insert(std::make_pair(due, pTimer));

	if (bReschedule)
		Reschedule(now);
}


////////////////////////////////////////////////////////////////////////
// EvCompactTimerService

EvCompactTimerService::EvCompactTimerService(ev::EventLoop &loop)
: m_pImpl(new Impl(loop))
{
}


EvCompactTimerService::~EvCompactTimerService() = default;


void EvCompactTimerService::CreateTimer(const unsigned int nTime,
	CCompactTimerClient &client,
	CCompactTimer::MEMBERCALLBACK pfnCallback,
	void *pArgument, CCompactTimer **const ppReference)
{
	m_pImpl->CreateTimer(nTime, client, pfnCallback, pArgument, ppReference);
}


void EvCompactTimerService::CreateTimer(const unsigned int nTime,
	CCompactTimer::STATICCALLBACK pfnCallback, void *pArgument,
	CCompactTimer **const ppReference)
{
	m_pImpl->CreateTimer(nTime, pfnCallback, pArgument, ppReference);
}


bool EvCompactTimerService::CancelTimer(CCompactTimer *&pTimer)
{
	return m_pImpl->CancelTimer(pTimer);
}


unsigned int EvCompactTimerService::CalculateTicks(const unsigned int nMicroseconds)
{
	// Just use microseconds internally
	return nMicroseconds;
}


const CCompactTimer &EvCompactTimerService::GetActiveTimer()
{
	return m_pImpl->GetActiveTimer();
}
