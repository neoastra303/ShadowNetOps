import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { LucideIcon } from "lucide-react";

interface MetricCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  className?: string;
}

export default function MetricCard({ title, value, icon: Icon, trend, className = "" }: MetricCardProps) {
  return (
    <Card className={`hover-elevate ${className}`} data-testid={`card-metric-${title.toLowerCase().replace(/\s+/g, '-')}`}>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="text-xs uppercase tracking-wide text-muted-foreground font-medium">
          {title}
        </CardTitle>
        <Icon className="h-4 w-4 text-primary" data-testid={`icon-${title.toLowerCase().replace(/\s+/g, '-')}`} />
      </CardHeader>
      <CardContent>
        <div className="text-3xl font-bold gradient-cyan-magenta" data-testid={`text-metric-value-${title.toLowerCase().replace(/\s+/g, '-')}`}>
          {value}
        </div>
        {trend && (
          <p className={`text-xs mt-1 ${trend.isPositive ? 'text-chart-3' : 'text-destructive'}`} data-testid="text-metric-trend">
            {trend.isPositive ? '↑' : '↓'} {Math.abs(trend.value)}% from last scan
          </p>
        )}
      </CardContent>
    </Card>
  );
}
