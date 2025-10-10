import OSINTTools from "@/components/OSINTTools";

export default function OSINTPage() {
  return (
    <div className="p-6" data-testid="page-osint">
      <div className="mb-6">
        <h1 className="text-3xl font-bold gradient-cyan-magenta mb-2">OSINT Operations</h1>
        <p className="text-muted-foreground">Open-source intelligence gathering and reconnaissance</p>
      </div>
      
      <div className="max-w-4xl">
        <OSINTTools />
      </div>
    </div>
  );
}
