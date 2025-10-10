import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/app-sidebar";
import Dashboard from "@/pages/Dashboard";
import TerminalPage from "@/pages/TerminalPage";
import ReconPage from "@/pages/ReconPage";
import VulnerabilitiesPage from "@/pages/VulnerabilitiesPage";
import PasswordPage from "@/pages/PasswordPage";
import OSINTPage from "@/pages/OSINTPage";
import NotFound from "@/pages/not-found";
import { Terminal } from "lucide-react";

function Router() {
  return (
    <Switch>
      <Route path="/" component={Dashboard} />
      <Route path="/terminal" component={TerminalPage} />
      <Route path="/recon" component={ReconPage} />
      <Route path="/vulnerabilities" component={VulnerabilitiesPage} />
      <Route path="/password" component={PasswordPage} />
      <Route path="/osint" component={OSINTPage} />
      <Route component={NotFound} />
    </Switch>
  );
}

export default function App() {
  const style = {
    "--sidebar-width": "16rem",
    "--sidebar-width-icon": "3rem",
  };

  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <SidebarProvider style={style as React.CSSProperties}>
          <div className="flex h-screen w-full bg-background">
            <AppSidebar />
            <div className="flex flex-col flex-1 overflow-hidden">
              <header className="flex items-center justify-between p-4 border-b border-primary/20 bg-card/50 backdrop-blur-sm">
                <div className="flex items-center gap-3">
                  <SidebarTrigger data-testid="button-sidebar-toggle" />
                  <div className="flex items-center gap-2">
                    <Terminal className="h-5 w-5 text-primary" />
                    <span className="font-bold text-primary">RedTeam Terminal</span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <div className="h-2 w-2 rounded-full bg-chart-3 animate-pulse" data-testid="indicator-status" />
                  <span className="text-xs text-muted-foreground">System Active</span>
                </div>
              </header>
              <main className="flex-1 overflow-auto">
                <Router />
              </main>
            </div>
          </div>
        </SidebarProvider>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}
