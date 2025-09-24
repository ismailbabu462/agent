#!/usr/bin/env python3
"""
PentoraSec Agent Build Script
Bu script, agent'ı ZAP ile birlikte paketler
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def build_agent():
    """Agent'ı ZAP ile birlikte build et"""
    
    print("🚀 Building PentoraSec Agent with Bundled ZAP...")
    
    # Gerekli dizinleri kontrol et
    agent_dir = Path(__file__).parent.absolute()
    zap_dir = agent_dir / "zap"
    
    print(f"📁 Agent directory: {agent_dir}")
    print(f"📁 ZAP directory: {zap_dir}")
    
    # ZAP dizinini kontrol et
    if not zap_dir.exists():
        print("❌ ZAP directory not found! Please add ZAP files to 'zap/' directory")
        print("📋 Required ZAP files:")
        print("   - Windows: zap.bat, zap-*.jar, lib/, etc.")
        print("   - Linux/macOS: zap.sh, zap-*.jar, lib/, etc.")
        return False
    
    # PyInstaller'ı kontrol et
    try:
        import PyInstaller
        print(f"✅ PyInstaller found: {PyInstaller.__version__}")
    except ImportError:
        print("❌ PyInstaller not found! Installing...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"])
    
    # Build komutunu çalıştır
    print("🔨 Building agent executable...")
    
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--clean",
        "--onefile",
        "--console",
        "--name", "PentoraSec-Agent",
        "--add-data", f"{zap_dir};zap",
        "--hidden-import", "requests",
        "--hidden-import", "psutil",
        "--hidden-import", "websockets",
        "--hidden-import", "asyncio",
        "agent-simple.py"
    ]
    
    print(f"🔧 Build command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, cwd=agent_dir, check=True, capture_output=True, text=True)
        print("✅ Build successful!")
        print(result.stdout)
        
        # Build çıktısını kontrol et
        dist_dir = agent_dir / "dist"
        exe_file = dist_dir / "PentoraSec-Agent.exe" if os.name == 'nt' else dist_dir / "PentoraSec-Agent"
        
        if exe_file.exists():
            print(f"✅ Executable created: {exe_file}")
            print(f"📊 File size: {exe_file.stat().st_size / (1024*1024):.1f} MB")
        else:
            print("❌ Executable not found!")
            return False
            
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Build failed: {e}")
        print(f"Error output: {e.stderr}")
        return False

if __name__ == "__main__":
    print("=" * 50)
    print("PENTORASEC AGENT BUILD SCRIPT")
    print("=" * 50)
    
    # Build agent
    if build_agent():
        print("✅ Agent build completed successfully!")
        print("\n🎉 Build process completed!")
        print("📁 Output files:")
        print("   - dist/PentoraSec-Agent.exe (Windows)")
        
    else:
        print("❌ Build failed!")
        sys.exit(1)
