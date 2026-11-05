import { Play, ExternalLink } from "lucide-react";
const WORKFLOW_URL = "https://github.com/teddyjeremy/Crypto-Secret-Exposure-Hunter/actions/workflows/crypto-scan.yml";
export function RunScanButton() {
 return <a className="btn" href={WORKFLOW_URL} target="_blank" rel="noreferrer">
  <Play size={14}/> Open scan workflow <ExternalLink size={13}/>
 </a>;
}
