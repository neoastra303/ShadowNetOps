import MetricCard from "../MetricCard";
import { Activity, Shield, Zap } from "lucide-react";

export default function MetricCardExample() {
  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      <MetricCard
        title="Active Scans"
        value="12"
        icon={Activity}
        trend={{ value: 8, isPositive: true }}
      />
      <MetricCard
        title="Vulnerabilities"
        value="47"
        icon={Shield}
        trend={{ value: 3, isPositive: false }}
      />
      <MetricCard
        title="Tools Running"
        value="5"
        icon={Zap}
      />
    </div>
  );
}
