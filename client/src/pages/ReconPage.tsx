import NetworkRecon from "@/components/NetworkRecon";

export default function ReconPage() {
  return (
    <div className="p-6" data-testid="page-recon">
      <div className="mb-6">
        <h1 className="text-3xl font-bold gradient-cyan-magenta mb-2">Network Reconnaissance</h1>
        <p className="text-muted-foreground">Scan and discover network targets, open ports, and services</p>
      </div>
      
      <div className="max-w-4xl">
        <NetworkRecon />
      </div>
    </div>
  );
}
