/**
 * RapidTriage - Minimal Forensic Sidebar Navigation
 * Section 34: Case File Visual Language (CASE ID, ENDPOINT, STATUS)
 * Clean, consistent in both Light and Dark mode.
 */

import React from 'react';
import { Layers, Clock, AlertTriangle, ShieldCheck, FileText, Folder } from 'lucide-react';
import { CaseDetails } from '../types/forensics';

export type NavTab = 'evidence' | 'timeline' | 'findings' | 'integrity';

interface SidebarProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  caseDetails: CaseDetails;
  findingsCount: number;
  onOpenReportModal: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  caseDetails,
  findingsCount,
  onOpenReportModal,
}) => {
  const navItems = [
    {
      id: 'evidence' as NavTab,
      label: 'Evidence',
      icon: Layers,
      count: undefined,
    },
    {
      id: 'timeline' as NavTab,
      label: 'Timeline',
      icon: Clock,
      count: undefined,
    },
    {
      id: 'findings' as NavTab,
      label: 'Findings',
      icon: AlertTriangle,
      count: findingsCount > 0 ? findingsCount : undefined,
    },
    {
      id: 'integrity' as NavTab,
      label: 'Integrity',
      icon: ShieldCheck,
      count: undefined,
    },
  ];

  return (
    <aside className="w-64 border-r flex flex-col justify-between shrink-0 select-none no-print transition-colors duration-150 bg-slate-900 border-slate-800 text-slate-100 dark:bg-[#080c14] dark:border-slate-800/80">
      <div>
        {/* Brand Lockup with Evidence Case Indicator */}
        <div className="px-5 py-4 border-b border-slate-800/80">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-2.5 h-2.5 bg-yellow-500 rounded-sm"></div>
              <h1 className="font-semibold text-sm tracking-tight text-white">RapidTriage</h1>
            </div>
            <span className="text-[10px] font-mono tracking-wider px-1.5 py-0.5 rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/20 uppercase font-semibold">
              TRIAGE
            </span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1 font-mono tracking-tight">
            Endpoint Forensic Investigation
          </p>
        </div>

        {/* Minimal Navigation */}
        <nav className="p-3 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors text-left ${
                  isActive
                    ? 'bg-slate-800 text-white font-semibold border-l-2 border-yellow-500 dark:bg-slate-800/90'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <Icon
                    className={`w-4 h-4 ${
                      isActive ? 'text-yellow-400' : 'text-slate-400'
                    }`}
                  />
                  <span>{item.label}</span>
                </div>
                {item.count !== undefined && (
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300 font-semibold">
                    {item.count}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Generate Case Report Action */}
        <div className="px-3 pt-2">
          <button
            onClick={onOpenReportModal}
            className="w-full flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-md text-amber-300 hover:text-white hover:bg-slate-800 border border-amber-500/30 transition-colors"
          >
            <FileText className="w-4 h-4 text-yellow-400" />
            <span>Generate Case Report</span>
          </button>
        </div>
      </div>

      {/* Section 34: Case File Visual Language */}
      <div className="p-4 border-t border-slate-800/80 bg-slate-950/70 dark:bg-[#06090e] space-y-2 font-mono">
        <div>
          <div className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">
            CASE ID
          </div>
          <div className="text-xs font-semibold text-slate-200 mt-0.5 truncate">
            {caseDetails.caseId}
          </div>
        </div>

        <div className="pt-1 border-t border-slate-800/50">
          <div className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">
            ENDPOINT
          </div>
          <div className="text-xs text-slate-300 mt-0.5 truncate">
            {caseDetails.endpoint}
          </div>
        </div>

        <div className="pt-1 border-t border-slate-800/50 flex items-center justify-between">
          <div>
            <div className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">
              STATUS
            </div>
            <div className="text-[11px] font-medium text-amber-400 mt-0.5 uppercase">
              {caseDetails.status === 'Requires Investigation'
                ? 'UNDER INVESTIGATION'
                : caseDetails.status}
            </div>
          </div>
          {caseDetails.isDemoData && (
            <span className="text-[9px] uppercase bg-slate-800 text-slate-400 px-1 py-0.5 rounded border border-slate-700">
              DEMO
            </span>
          )}
        </div>
      </div>
    </aside>
  );
};
