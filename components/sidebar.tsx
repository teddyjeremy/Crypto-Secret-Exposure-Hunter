"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Activity, FileSearch, LayoutDashboard, Mail, Settings, Radar, Globe } from "lucide-react";
const links = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/findings", label: "Findings", icon: FileSearch },
  { href: "/websites", label: "Website scanner", icon: Globe },
  { href: "/disclosures", label: "Disclosures", icon: Mail },
  { href: "/settings", label: "Configuration", icon: Settings }
];
export function Sidebar() {
  const pathname = usePathname();
  return <aside className="sidebar">
    <Link href="/" className="brand"><span className="brand-mark"><Radar size={19}/></span><span><span className="brand-name">Exposure Hunter</span><div className="brand-sub">BLOCKCHAIN SECURITY</div></span></Link>
    <div className="nav-label">WORKSPACE</div>
    <nav className="nav-links">{links.map(item => { const Icon=item.icon; const active=pathname===item.href || (item.href!=="/" && pathname.startsWith(item.href)); return <Link key={item.href} href={item.href} className={`nav-link ${active?"active":""}`}><Icon size={16}/>{item.label}</Link>; })}</nav>
    <div className="nav-label">SYSTEM</div>
    <div className="nav-link"><Activity size={16}/> Scanner worker</div>
    <div className="side-bottom"><div><span className="online-dot"/>DEFENSIVE MODE</div><div style={{marginTop:7}}>Credentials are redacted at source. No wallet access or transaction capabilities.</div></div>
  </aside>;
}