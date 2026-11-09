import React from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert, Shield } from 'lucide-react';
import { RiskLevel } from '../../types/security';

interface RiskBadgeProps {
  score: number;
  level?: RiskLevel;
  showScore?: boolean;
  size?: 'sm' | 'md' | 'lg';
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({
  score,
  level,
  showScore = true,
  size = 'md',
}) => {
  // Determine risk level based on score if not explicitly provided
  const riskLevel: RiskLevel =
    level ||
    (score >= 80 ? 'critical' : score >= 55 ? 'high' : score >= 25 ? 'moderate' : 'low');

  const config = {
    low: {
      label: 'Safe',
      textColor: 'text-emerald-400',
      bgColor: 'bg-emerald-950/40',
      borderColor: 'border-emerald-800/40',
      icon: ShieldCheck,
    },
    moderate: {
      label: 'Moderate',
      textColor: 'text-amber-400',
      bgColor: 'bg-amber-950/40',
      borderColor: 'border-amber-800/40',
      icon: AlertTriangle,
    },
    high: {
      label: 'Suspicious',
      textColor: 'text-orange-400',
      bgColor: 'bg-orange-950/40',
      borderColor: 'border-orange-800/40',
      icon: ShieldAlert,
    },
    critical: {
      label: 'Critical Threat',
      textColor: 'text-rose-400',
      bgColor: 'bg-rose-950/40',
      borderColor: 'border-rose-800/40',
      icon: ShieldAlert,
    },
  }[riskLevel];

  const Icon = config.icon;

  const sizeClasses = {
    sm: 'text-xs py-0.5 px-2 gap-1.5',
    md: 'text-xs py-1 px-2.5 gap-1.5',
    lg: 'text-sm py-1.5 px-3 gap-2',
  }[size];

  const iconSizes = {
    sm: 'h-3.5 w-3.5',
    md: 'h-4 w-4',
    lg: 'h-4.5 w-4.5',
  }[size];

  return (
    <span
      className={`inline-flex items-center rounded-md border font-medium ${config.bgColor} ${config.borderColor} ${config.textColor} ${sizeClasses}`}
    >
      <Icon className={`${iconSizes} shrink-0`} />
      <span>{config.label}</span>
      {showScore && (
        <span className="font-mono tabular-nums opacity-90">
          ({score}/100)
        </span>
      )}
    </span>
  );
};
