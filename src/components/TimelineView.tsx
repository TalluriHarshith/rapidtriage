/**
 * RapidTriage - Unified Timeline (Forensic Investigation Style)
 * Implements Section 35 (Evidence Tags: [BROWSER], [USB], [EXECUTION], [NETWORK], [REVIEW], [SUSPICIOUS])
 * Section 36 & 37 (Vertical Investigation Spine & Investigation Markers)
 * Section 38 (Correlation Visualization & Connector)
 * Section 40-45 (Full Light and Dark Theme Support)
 */

import React, { useState, useMemo } from 'react';
import {
  Search,
  Globe,
  HardDrive,
  Cpu,
  Radio,
  X,
  Link2,
  Clock,
  ArrowRight,
  Filter,
  AlertCircle,
  CheckCircle2,
} from 'lucide-react';
import {
  StandardizedEvent,
  ForensicArtifactType,
  RiskStatus,
} from '../types/forensics';
import { EventDetailPanel } from './EventDetailPanel';

interface TimelineViewProps {
  events: StandardizedEvent[];
  selectedEventId: string | null;
  onSelectEvent: (eventId: string | null) => void;
  filterCorrelationId: string | null;
  onClearCorrelationFilter: () => void;
  onFocusCorrelation: (corrId: string) => void;
}

export const TimelineView: React.FC<TimelineViewProps> = ({
  events,
  selectedEventId,
  onSelectEvent,
  filterCorrelationId,
  onClearCorrelationFilter,
  onFocusCorrelation,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [artifactFilter, setArtifactFilter] = useState<'all' | ForensicArtifactType>('all');
  const [statusFilter, setStatusFilter] = useState<'all' | RiskStatus>('all');
  const [timeRangeFilter, setTimeRangeFilter] = useState<string>('all');

  // Compute time range options dynamically
  const timeHours = useMemo(() => {
    const hours = new Set<string>();
    events.forEach((e) => {
      const timePart = e.timestamp.split(' ')[1];
      if (timePart) {
        const hour = timePart.substring(0, 2) + ':00 - ' + timePart.substring(0, 2) + ':59';
        hours.add(hour);
      }
    });
    return Array.from(hours).sort();
  }, [events]);

  const selectedEvent = useMemo(
    () => events.find((e) => e.event_id === selectedEventId) || null,
    [events, selectedEventId]
  );

  // Filtered events
  const filteredEvents = useMemo(() => {
    return events.filter((e) => {
      if (filterCorrelationId && e.correlation_id !== filterCorrelationId) {
        return false;
      }
      if (artifactFilter !== 'all' && e.artifact !== artifactFilter) {
        return false;
      }
      if (statusFilter !== 'all' && e.risk_status !== statusFilter) {
        return false;
      }
      if (timeRangeFilter !== 'all') {
        const hourPrefix = timeRangeFilter.substring(0, 2);
        const timePart = e.timestamp.split(' ')[1] || '';
        if (!timePart.startsWith(hourPrefix)) {
          return false;
        }
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matches =
          e.description.toLowerCase().includes(q) ||
          e.event_id.toLowerCase().includes(q) ||
          (e.process && e.process.toLowerCase().includes(q)) ||
          (e.path && e.path.toLowerCase().includes(q)) ||
          (e.url && e.url.toLowerCase().includes(q)) ||
          (e.device && e.device.toLowerCase().includes(q)) ||
          (e.local_address && e.local_address.toLowerCase().includes(q)) ||
          (e.remote_address && e.remote_address.toLowerCase().includes(q)) ||
          (e.reason && e.reason.toLowerCase().includes(q));
        if (!matches) return false;
      }
      return true;
    });
  }, [events, filterCorrelationId, artifactFilter, statusFilter, timeRangeFilter, searchQuery]);

  const handleClearAll = () => {
    setSearchQuery('');
    setArtifactFilter('all');
    setStatusFilter('all');
    setTimeRangeFilter('all');
    onClearCorrelationFilter();
  };

  const hasActiveFilters =
    searchQuery.trim() !== '' ||
    artifactFilter !== 'all' ||
    statusFilter !== 'all' ||
    timeRangeFilter !== 'all' ||
    filterCorrelationId !== null;

  // Section 35: Evidence Tag styling
  const renderArtifactTag = (artifact: ForensicArtifactType) => {
    switch (artifact) {
      case 'browser':
        return (
          <span className="font-mono text-[10px] font-semibold px-1.5 py-0.5 rounded border tracking-wider bg-sky-50 text-sky-800 border-sky-300 dark:bg-sky-950/40 dark:text-sky-300 dark:border-sky-800/60">
            [BROWSER]
          </span>
        );
      case 'usb':
        return (
          <span className="font-mono text-[10px] font-semibold px-1.5 py-0.5 rounded border tracking-wider bg-emerald-50 text-emerald-800 border-emerald-300 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800/60">
            [USB]
          </span>
        );
      case 'execution':
        return (
          <span className="font-mono text-[10px] font-semibold px-1.5 py-0.5 rounded border tracking-wider bg-purple-50 text-purple-800 border-purple-300 dark:bg-purple-950/40 dark:text-purple-300 dark:border-purple-800/60">
            [EXECUTION]
          </span>
        );
      case 'network':
        return (
          <span className="font-mono text-[10px] font-semibold px-1.5 py-0.5 rounded border tracking-wider bg-indigo-50 text-indigo-800 border-indigo-300 dark:bg-indigo-950/40 dark:text-indigo-300 dark:border-indigo-800/60">
            [NETWORK]
          </span>
        );
    }
  };

  // Section 35: Status Evidence Tags
  const renderStatusTag = (status: RiskStatus) => {
    switch (status) {
      case 'suspicious':
        return (
          <span className="font-mono text-[10px] font-bold px-1.5 py-0.5 rounded border tracking-wider bg-red-50 text-red-800 border-red-300 dark:bg-red-950/60 dark:text-red-300 dark:border-red-800/80 flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-red-600 dark:bg-red-400"></span>
            <span>[REVIEW]</span>
          </span>
        );
      case 'review':
        return (
          <span className="font-mono text-[10px] font-semibold px-1.5 py-0.5 rounded border tracking-wider bg-amber-50 text-amber-800 border-amber-300 dark:bg-amber-950/60 dark:text-amber-300 dark:border-amber-800/70">
            [REVIEW]
          </span>
        );
      case 'normal':
        return (
          <span className="font-mono text-[10px] px-1.5 py-0.5 rounded border tracking-wider bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-800/60 dark:text-slate-400 dark:border-slate-700/60">
            [NORMAL]
          </span>
        );
    }
  };

  return (
    <div className="flex-1 flex overflow-hidden bg-slate-50 text-slate-900 dark:bg-[#0c1017] dark:text-slate-100 transition-colors duration-150">
      {/* Main Timeline Area */}
      <div className="flex-1 flex flex-col h-full overflow-hidden">
        {/* Top Filters Bar */}
        <div className="p-4 border-b space-y-3 shrink-0 bg-white border-slate-200 dark:bg-[#090d14] dark:border-slate-800">
          {/* Row 1: Search input & Clear */}
          <div className="flex items-center gap-3">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search events, processes, paths, IP sockets, files..."
                className="w-full text-xs pl-9 pr-8 py-2 rounded-md border transition-colors font-mono focus:outline-none bg-slate-50 border-slate-300 text-slate-900 focus:border-slate-500 placeholder:text-slate-400 dark:bg-[#111622] dark:border-slate-700/70 dark:text-slate-200 dark:placeholder:text-slate-500"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery('')}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {hasActiveFilters && (
              <button
                onClick={handleClearAll}
                className="px-3 py-2 text-xs font-mono rounded transition-colors text-slate-600 hover:bg-slate-100 dark:text-slate-400 dark:hover:text-slate-200 dark:hover:bg-slate-800"
              >
                Clear Filters
              </button>
            )}
          </div>

          {/* Row 2: Minimal Filter Chips (Artifact, Status, Hour) */}
          <div className="flex flex-wrap items-center justify-between gap-3 text-xs">
            <div className="flex flex-wrap items-center gap-2.5">
              {/* Artifact Segmented Control */}
              <div className="flex items-center gap-1 p-0.5 rounded-md border bg-slate-100 border-slate-300 dark:bg-[#121824] dark:border-slate-800">
                <span className="text-[11px] font-mono text-slate-500 px-2 uppercase">Artifact:</span>
                {(['all', 'browser', 'usb', 'execution', 'network'] as const).map((art) => (
                  <button
                    key={art}
                    onClick={() => setArtifactFilter(art)}
                    className={`px-2 py-0.5 rounded text-xs capitalize transition-colors font-medium ${
                      artifactFilter === art
                        ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-800 dark:text-slate-100'
                        : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200'
                    }`}
                  >
                    {art}
                  </button>
                ))}
              </div>

              {/* Status Filter */}
              <div className="flex items-center gap-1 p-0.5 rounded-md border bg-slate-100 border-slate-300 dark:bg-[#121824] dark:border-slate-800">
                <span className="text-[11px] font-mono text-slate-500 px-2 uppercase">Status:</span>
                {(
                  [
                    { id: 'all', label: 'All' },
                    { id: 'normal', label: 'Normal' },
                    { id: 'review', label: 'Review' },
                    { id: 'suspicious', label: 'Suspicious' },
                  ] as const
                ).map((st) => (
                  <button
                    key={st.id}
                    onClick={() => setStatusFilter(st.id)}
                    className={`px-2 py-0.5 rounded text-xs transition-colors font-medium ${
                      statusFilter === st.id
                        ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-800 dark:text-slate-100'
                        : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200'
                    }`}
                  >
                    {st.label}
                  </button>
                ))}
              </div>

              {/* Time Range Filter */}
              {timeHours.length > 0 && (
                <div className="flex items-center gap-1 px-2 py-1 rounded-md border text-xs bg-slate-100 border-slate-300 dark:bg-[#121824] dark:border-slate-800">
                  <span className="text-[11px] font-mono text-slate-500 uppercase">Hour:</span>
                  <select
                    value={timeRangeFilter}
                    onChange={(e) => setTimeRangeFilter(e.target.value)}
                    className="bg-transparent font-mono text-xs focus:outline-none cursor-pointer text-slate-800 dark:text-slate-200"
                  >
                    <option value="all" className="bg-white text-slate-900 dark:bg-[#121824] dark:text-slate-300">
                      All hours
                    </option>
                    {timeHours.map((hour) => (
                      <option key={hour} value={hour} className="bg-white text-slate-900 dark:bg-[#121824] dark:text-slate-300">
                        {hour}
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            <div className="text-[11px] font-mono text-slate-500">
              {filteredEvents.length} of {events.length} records
            </div>
          </div>

          {/* Section 38: Active Correlation Filter Notice */}
          {filterCorrelationId && (
            <div className="flex items-center justify-between px-3 py-2 rounded text-xs border bg-amber-50 text-amber-900 border-amber-300 dark:bg-amber-950/40 dark:text-amber-200 dark:border-amber-800/60 font-mono">
              <div className="flex items-center gap-2">
                <Link2 className="w-3.5 h-3.5 text-yellow-600 dark:text-yellow-400" />
                <span>
                  CORRELATION — <strong>{filterCorrelationId}</strong> ({filteredEvents.length} related events • Requires Investigation)
                </span>
              </div>
              <button
                onClick={onClearCorrelationFilter}
                className="text-yellow-700 dark:text-yellow-400 hover:underline font-bold text-xs"
              >
                Reset Filter
              </button>
            </div>
          )}
        </div>

        {/* Section 36 & 37: Chronological Vertical Timeline with Forensic Spine */}
        <div className="flex-1 overflow-y-auto p-6">
          {filteredEvents.length === 0 ? (
            <div className="h-64 flex flex-col items-center justify-center text-center">
              <Filter className="w-8 h-8 text-slate-400 mb-2" />
              <p className="text-sm text-slate-500 dark:text-slate-400">
                No events match current filter criteria.
              </p>
              <button
                onClick={handleClearAll}
                className="mt-3 px-3 py-1.5 text-xs font-medium rounded transition-colors bg-slate-200 hover:bg-slate-300 text-slate-800 dark:bg-slate-800 dark:hover:bg-slate-700 dark:text-slate-200"
              >
                Clear all filters
              </button>
            </div>
          ) : (
            <div className="max-w-4xl mx-auto relative pl-8 before:content-[''] before:absolute before:left-4 before:top-3 before:bottom-3 before:w-[2px] before:bg-slate-300 dark:before:bg-slate-800">
              <div className="space-y-4">
                {filteredEvents.map((evt) => {
                  const isSelected = evt.event_id === selectedEventId;
                  const isSuspicious = evt.risk_status === 'suspicious';
                  const isReview = evt.risk_status === 'review';

                  return (
                    <div
                      key={evt.event_id}
                      onClick={() => onSelectEvent(evt.event_id)}
                      className={`relative flex items-start gap-4 p-3.5 rounded-lg border transition-all cursor-pointer ${
                        isSelected
                          ? 'border-yellow-500 ring-2 ring-yellow-500/30 bg-amber-50/40 dark:bg-slate-800/90'
                          : isSuspicious
                          ? 'border-red-300 bg-red-50/30 hover:border-red-400 dark:border-red-900/50 dark:bg-[#160e12] dark:hover:border-red-700/60'
                          : 'border-slate-200 bg-white hover:border-slate-300 dark:border-slate-800/80 dark:bg-[#101622] dark:hover:border-slate-700'
                      }`}
                    >
                      {/* Section 37: Investigation Marker */}
                      <div
                        className={`absolute -left-[2.15rem] top-5 w-3 h-3 rounded-full ring-4 flex items-center justify-center transition-transform ${
                          isSuspicious
                            ? 'bg-yellow-500 ring-yellow-400/30 dark:ring-yellow-950 scale-110'
                            : isReview
                            ? 'bg-amber-400 ring-amber-300/30 dark:ring-amber-950'
                            : 'bg-slate-400 ring-slate-200 dark:bg-slate-600 dark:ring-[#0c1017]'
                        }`}
                        title={isSuspicious ? 'Investigation Marker: Investigate this event' : undefined}
                      >
                        {isSuspicious && (
                          <div className="w-1 h-1 rounded-full bg-black"></div>
                        )}
                      </div>

                      {/* Left: Tabular Timestamp */}
                      <div className="shrink-0 w-20 text-left pt-0.5">
                        <div className="text-xs font-mono font-bold text-slate-800 dark:text-slate-200">
                          {evt.timestamp.split(' ')[1] || evt.timestamp}
                        </div>
                        <div className="text-[10px] font-mono text-slate-500 mt-0.5">
                          {evt.event_id}
                        </div>
                      </div>

                      {/* Middle: Content */}
                      <div className="flex-1 min-w-0">
                        {/* Tags Header */}
                        <div className="flex flex-wrap items-center gap-2 mb-1">
                          {renderArtifactTag(evt.artifact)}
                          {renderStatusTag(evt.risk_status)}
                          <span className="text-xs font-medium text-slate-700 dark:text-slate-300 truncate">
                            {evt.event_type}
                          </span>

                          {/* Correlation Tag */}
                          {evt.correlation_id && (
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                onFocusCorrelation(evt.correlation_id!);
                              }}
                              className="ml-auto text-[10px] font-mono px-1.5 py-0.2 rounded border flex items-center gap-1 font-semibold transition-colors bg-yellow-50 text-yellow-800 border-yellow-300 hover:bg-yellow-100 dark:bg-yellow-950/40 dark:text-yellow-300 dark:border-yellow-800/60 dark:hover:bg-yellow-900/40"
                              title="Focus this correlation chain"
                            >
                              <Link2 className="w-3 h-3 text-yellow-500" />
                              <span>{evt.correlation_id}</span>
                            </button>
                          )}
                        </div>

                        {/* Description */}
                        <div className="text-xs font-medium text-slate-800 dark:text-slate-200 mt-1">
                          {evt.description}
                        </div>

                        {/* Path / Socket */}
                        {(evt.path || evt.url || evt.remote_address) && (
                          <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 mt-1 truncate max-w-xl">
                            {evt.path || evt.url || `${evt.local_address || ''} → ${evt.remote_address}`}
                          </div>
                        )}

                        {/* Suspicious Reason Note */}
                        {evt.reason && (
                          <div className="text-[11px] mt-1.5 flex items-center gap-1.5 font-medium text-red-700 dark:text-red-300">
                            <AlertCircle className="w-3.5 h-3.5 text-red-500 shrink-0" />
                            <span>{evt.reason}</span>
                          </div>
                        )}
                      </div>

                      {/* Right: Quick Action Indicator */}
                      <div className="shrink-0 pt-0.5 text-slate-400">
                        <ArrowRight className="w-3.5 h-3.5" />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Docked Event Detail Panel */}
      {selectedEvent && (
        <EventDetailPanel
          event={selectedEvent}
          onClose={() => onSelectEvent(null)}
          onViewRelatedEvents={(corrId) => onFocusCorrelation(corrId)}
        />
      )}
    </div>
  );
};
