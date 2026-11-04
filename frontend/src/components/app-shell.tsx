import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, Outlet, useNavigate } from "@tanstack/react-router";
import {
  Activity,
  Database,
  Filter,
  Gauge,
  Globe,
  House,
  List,
  LogOut,
  type LucideIcon,
  Menu,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  Server,
  Settings,
  ShieldBan,
  Split,
  Users,
  UsersRound,
} from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import { Button } from "./ui/button";

import { BlockingControl } from "@/features/blocking";
import { NodeChangeBanner } from "@/features/node-settings";
import { errorMessage, setCsrfToken } from "@/lib/api/client";
import { api, queries } from "@/lib/api/hooks";
import { cn } from "@/lib/utils";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
}

const NAV: Array<{ heading?: string; items: NavItem[] }> = [
  {
    items: [
      { to: "/", label: "Overview", icon: Gauge },
      { to: "/queries", label: "Query Explorer", icon: Activity },
      { to: "/clients", label: "Clients", icon: Users },
      { to: "/network", label: "Network", icon: Network },
    ],
  },
  {
    heading: "Filtering",
    items: [
      { to: "/filtering/rules", label: "Rules", icon: ShieldBan },
      { to: "/filtering/lists", label: "Sources", icon: List },
      { to: "/groups", label: "Groups", icon: UsersRound },
    ],
  },
  {
    heading: "Node",
    items: [
      { to: "/dns/records", label: "Local DNS", icon: House },
      { to: "/dns/upstreams", label: "Upstreams", icon: Globe },
      { to: "/dns/forwarders", label: "Conditional forwarding", icon: Split },
      { to: "/dns/cache", label: "Cache", icon: Database },
      { to: "/system", label: "System", icon: Server },
      { to: "/settings", label: "Settings", icon: Settings },
    ],
  },
];

function Navigation({ collapsed, onNavigate }: { collapsed: boolean; onNavigate?: () => void }) {
  return (
    <nav aria-label="Main" className="flex-1 space-y-4 overflow-y-auto p-2">
      {NAV.map((section, index) => (
        <div key={section.heading ?? index} className="space-y-0.5">
          {section.heading && !collapsed && (
            <p className="px-2 pb-1 text-xs font-medium text-text-muted">{section.heading}</p>
          )}
          {section.items.map(({ to, label, icon: Icon }) => (
            <Link
              key={to}
              to={to}
              onClick={onNavigate}
              activeOptions={{ exact: to === "/" }}
              aria-label={collapsed ? label : undefined}
              title={collapsed ? label : undefined}
              className={cn(
                "flex h-9 items-center gap-2.5 rounded-md px-2.5 text-sm text-text-secondary hover:bg-surface-muted hover:text-text data-[status=active]:bg-accent-soft data-[status=active]:font-medium data-[status=active]:text-text",
                collapsed && "justify-center px-0",
              )}
            >
              <Icon aria-hidden className="size-4 shrink-0" />
              {!collapsed && label}
            </Link>
          ))}
        </div>
      ))}
    </nav>
  );
}

function Brand({ collapsed }: { collapsed: boolean }) {
  return (
    <div className={cn("flex h-14 shrink-0 items-center gap-2 border-b border-border px-3", collapsed && "justify-center px-0")}>
      <span className="flex size-7 items-center justify-center rounded-md bg-accent text-accent-text">
        <Filter aria-hidden className="size-4" />
      </span>
      {!collapsed && <span className="font-semibold">FerrixDNS</span>}
    </div>
  );
}

export function AppShell() {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const session = useQuery(queries.session());
  const client = useQueryClient();
  const navigate = useNavigate();

  useEffect(() => {
    if (session.data) setCsrfToken(session.data.csrf_token);
  }, [session.data]);

  async function signOut() {
    try {
      await api.logout();
    } catch (error) {
      toast.error(errorMessage(error));
      return;
    }
    setCsrfToken(undefined);
    client.clear();
    await navigate({ to: "/login" });
  }

  return (
    <div className="flex h-dvh">
      <aside
        className={cn(
          "hidden shrink-0 flex-col border-r border-border bg-surface lg:flex",
          collapsed ? "w-16" : "w-60",
        )}
      >
        <Brand collapsed={collapsed} />
        <Navigation collapsed={collapsed} />
        <div className="border-t border-border p-2">
          <Button
            variant="ghost"
            size="icon"
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            className={cn(collapsed && "mx-auto flex")}
            onClick={() => setCollapsed((value) => !value)}
          >
            {collapsed ? (
              <PanelLeftOpen aria-hidden className="size-4" />
            ) : (
              <PanelLeftClose aria-hidden className="size-4" />
            )}
          </Button>
        </div>
      </aside>

      {mobileOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <button
            type="button"
            aria-label="Close navigation"
            className="absolute inset-0 bg-black/50"
            onClick={() => setMobileOpen(false)}
          />
          <aside className="absolute inset-y-0 left-0 flex w-60 flex-col border-r border-border bg-surface">
            <Brand collapsed={false} />
            <Navigation collapsed={false} onNavigate={() => setMobileOpen(false)} />
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center gap-2 border-b border-border bg-surface px-4">
          <Button
            variant="ghost"
            size="icon"
            aria-label="Open navigation"
            className="lg:hidden"
            onClick={() => setMobileOpen(true)}
          >
            <Menu aria-hidden className="size-4" />
          </Button>
          <div className="ml-auto flex min-w-0 items-center gap-2">
            <BlockingControl />
            {session.data && (
              <span className="hidden truncate text-sm text-text-secondary sm:inline">
                {session.data.username}
              </span>
            )}
            <Button variant="ghost" size="sm" onClick={() => void signOut()}>
              <LogOut aria-hidden className="size-3.5" />
              <span className="sr-only sm:not-sr-only">Sign out</span>
            </Button>
          </div>
        </header>
        <NodeChangeBanner />
        <main className="min-h-0 flex-1 overflow-y-auto p-4 lg:p-6">
          <div className="mx-auto max-w-[1600px]">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
