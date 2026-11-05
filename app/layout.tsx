import type { Metadata } from "next";
import "./globals.css";
import { Sidebar } from "@/components/sidebar";
export const metadata: Metadata = {
  title: "Crypto Secret Exposure Hunter",
  description: "Defensive public repository secret exposure research and responsible disclosure."
};
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body><div className="shell"><Sidebar /><main className="main">{children}</main></div></body></html>;
}