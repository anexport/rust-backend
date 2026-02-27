import Link from 'next/link';
import { MapPin } from 'lucide-react';

export default function Home() {
  return (
    <div className="fixed inset-0 z-[100] flex flex-col bg-[#0e7149] text-white overflow-hidden font-sans selection:bg-white/20">
      {/* Top right MAP button */}
      <div className="absolute top-12 right-6">
        <button className="flex items-center gap-1.5 bg-white text-black px-4 py-2 rounded-full font-bold text-sm tracking-wide shadow-sm hover:bg-gray-100 transition-colors">
          <MapPin className="w-4 h-4" /> MAP
        </button>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col items-center justify-center -mt-16">
        {/* Logo Icon Box */}
        <div className="w-[5.5rem] h-[5.5rem] bg-[#0e7149] rounded-3xl border-[3px] border-[#0a4d31] flex flex-col items-center justify-center shadow-inner relative overflow-hidden mb-4">
          <svg width="44" height="44" viewBox="0 0 32 32" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="mt-1">
            <path d="M16 4v22" />
            <path d="M8 16l8-10 8 10" />
            <path d="M6 24l10-10 10 10" />
            <path d="M12 28h8" />
          </svg>
        </div>

        {/* Brand Name */}
        <h1 className="text-6xl font-extrabold tracking-tight mb-8 lowercase">
          forest
        </h1>

        {/* Subtitle */}
        <div className="text-center text-[1.4rem] font-medium leading-[1.3]">
          <p>London&apos;s</p>
          <p className="italic">homegrown</p>
          <p>ebike</p>
        </div>
      </div>

      {/* Bottom Buttons */}
      <div className="px-6 pb-12 w-full max-w-sm mx-auto flex flex-col gap-4">
        <Link 
          href="/api/auth/signup" 
          className="w-full bg-white text-black text-center py-4 rounded-full font-bold text-[1.05rem] tracking-wide hover:bg-gray-100 transition-colors"
        >
          SIGN UP
        </Link>
        <Link 
          href="/api/auth/login" 
          className="w-full bg-[#0a2e1e] text-white text-center py-4 rounded-full font-bold text-[1.05rem] tracking-wide hover:bg-[#072115] transition-colors"
        >
          SIGN IN
        </Link>
      </div>
    </div>
  );
}
