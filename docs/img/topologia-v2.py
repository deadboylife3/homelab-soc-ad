from PIL import Image, ImageDraw, ImageFont
import math, sys

S = 2
W, H = 1600, 1110
img = Image.new("RGB", (W*S, H*S), "#F7F8FA")
d = ImageDraw.Draw(img)

FD = "/usr/share/fonts/opentype/inter/"
def F(w, size):
    return ImageFont.truetype(FD + {"r":"Inter-Regular.otf","m":"Inter-Medium.otf","s":"Inter-SemiBold.otf","b":"Inter-Bold.otf"}[w], size*S)
MONO = lambda size: ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", size*S)

INK="#1F2937"; MUTED="#5B6472"; LINE="#9AA3AF"
C = {
 "host":  ("#EEF1F5","#64748B"),
 "wan":   ("#E9EDF2","#94A3B8"),
 "fw":    ("#FFF4E5","#D97706"),
 "cli":   ("#EAF2FD","#2F6FD6"),
 "srv":   ("#E9F7EF","#1F9D5C"),
 "atk":   ("#FDECEC","#D04545"),
 "log":   "#E07B00",
 "adm":   "#475569",
}

def rr(x1,y1,x2,y2,fill,outline,r=14,w=2,dash=False):
    d.rounded_rectangle([x1*S,y1*S,x2*S,y2*S], r*S, fill=fill, outline=None if dash else outline, width=w*S)
    if dash:
        dline([(x1+r,y1),(x2-r,y1)],outline,w,10,6); dline([(x1+r,y2),(x2-r,y2)],outline,w,10,6)
        dline([(x1,y1+r),(x1,y2-r)],outline,w,10,6); dline([(x2,y1+r),(x2,y2-r)],outline,w,10,6)
        for cx,cy,a0 in [(x1+r,y1+r,180),(x2-r,y1+r,270),(x2-r,y2-r,0),(x1+r,y2-r,90)]:
            d.arc([(cx-r)*S,(cy-r)*S,(cx+r)*S,(cy+r)*S],a0,a0+90,fill=outline,width=w*S)

def text(x,y,s,font,fill=INK,anchor="la"):
    d.text((x*S,y*S),s,font=font,fill=fill,anchor=anchor)

def dline(pts,color,w=2,on=9,off=6):
    for (x1,y1),(x2,y2) in zip(pts,pts[1:]):
        L=math.hypot(x2-x1,y2-y1);
        if L==0: continue
        ux,uy=(x2-x1)/L,(y2-y1)/L; t=0
        while t<L:
            e=min(t+on,L)
            d.line([((x1+ux*t)*S,(y1+uy*t)*S),((x1+ux*e)*S,(y1+uy*e)*S)],fill=color,width=w*S)
            t+=on+off

def line(pts,color,w=2):
    d.line([(x*S,y*S) for x,y in pts],fill=color,width=w*S,joint="curve")

def arrow(x,y,ang,color,size=11):
    a=math.radians(ang)
    p=[(x,y),(x-size*math.cos(a-0.42),y-size*math.sin(a-0.42)),(x-size*math.cos(a+0.42),y-size*math.sin(a+0.42))]
    d.polygon([(px*S,py*S) for px,py in p],fill=color)

def pill(x,y,s,fg,bg,font=None):
    font=font or F("m",13)
    tw=d.textlength(s,font=font)/S
    rr(x,y,x+tw+20,y+26,bg,bg,r=13,w=1)
    text(x+10,y+13,s,font,fg,"lm")
    return x+tw+20

def card(x1,y1,x2,y2,accent,title,lines,tag=None):
    rr(x1+3,y1+4,x2+3,y2+4,"#E3E6EB","#E3E6EB",r=12,w=1)
    rr(x1,y1,x2,y2,"#FFFFFF","#D5DAE1",r=12,w=1)
    d.rounded_rectangle([x1*S,y1*S,(x1+6)*S,y2*S],3*S,fill=accent)
    text(x1+20,y1+16,title,F("s",17))
    yy=y1+46
    for i,(s,f,col) in enumerate(lines):
        text(x1+20,yy,s,f,col); yy+=24
    if tag:
        pill(x2-d.textlength(tag[0],font=F("m",12))/S-32,y1+14,tag[0],tag[1],tag[2],F("m",12))

# ---------- title ----------
text(60,46,"Homelab SOC · Topologia v2",F("b",30))
text(60,84,"Rede segmentada: todo tráfego entre zonas atravessa o pfSense e é registrado no SIEM",F("r",16),MUTED)

# ---------- HOST ----------
hx1,hy1,hx2,hy2 = 560,125,1040,215
rr(hx1,hy1,hx2,hy2,C["host"][0],C["host"][1],r=14,w=2,dash=True)
text(800,150,"Windows 11 HOST · estação do analista",F("s",18),INK,"mm")
text(800,178,"192.168.252.1 · fora do laboratório",F("r",14),MUTED,"mm")
text(800,200,"Splunk Web · SSH · painel do pfSense",F("r",13),MUTED,"mm")

# ---------- WAN band ----------
rr(60,260,1540,306,C["wan"][0],C["wan"][1],r=10,w=1)
text(80,283,"WAN",F("b",15),"#334155","lm")
text(130,283,"VMnet8 (NAT VMware) · 192.168.252.0/24 · saída para a internet",F("r",14),MUTED,"lm")
text(1520,283,"port forward restrito a HOST_ANALISTA",F("m",13),"#334155","rm")

# HOST -> WAN -> pfSense admin link
line([(800,hy2),(800,260)],C["adm"],2)
line([(800,306),(800,345)],C["adm"],2); arrow(800,345,90,C["adm"])
lx=812
for s in ["443 painel","8000 Splunk Web","2222 SSH Ubuntu","2223 SSH DC01"]:
    lx=pill(lx,230-0,s,"#FFFFFF",C["adm"],F("m",12))+6

# ---------- pfSense ----------
fx1,fy1,fx2,fy2 = 590,345,1010,470
rr(fx1+3,fy1+4,fx2+3,fy2+4,"#EADFCF","#EADFCF",r=16,w=1)
rr(fx1,fy1,fx2,fy2,C["fw"][0],C["fw"][1],r=16,w=2)
text(800,375,"pfSense",F("b",22),"#92400E","mm")
text(800,404,"Firewall · Gateway · NAT · DHCP",F("m",15),"#92400E","mm")
text(800,436,"default deny · aliases · log nos bloqueios",F("r",13),"#9A5B12","mm")

# ---------- zones ----------
zy1,zy2 = 590,930
zones = [
 (60,500,"cli","CLIENTS","VMnet2 · 10.0.1.0/24 · gw 10.0.1.1"),
 (560,1040,"srv","SERVERS","VMnet3 · 10.0.2.0/24 · gw 10.0.2.1"),
 (1100,1540,"atk","ATTACKER","VMnet4 · 10.0.3.0/24 · gw 10.0.3.1"),
]
for x1,x2,k,name,sub in zones:
    rr(x1,zy1,x2,zy2,C[k][0],C[k][1],r=16,w=2)
    text(x1+20,zy1+24,name,F("b",17),C[k][1],"lm")
    text(x1+20,zy1+50,sub,F("r",13),MUTED,"lm")

# links pfSense -> zones
line([(700,fy2),(700,520),(280,520),(280,zy1)],C["cli"][1],3); arrow(280,zy1,90,C["cli"][1],13)
line([(800,fy2),(800,zy1)],C["srv"][1],3); arrow(800,zy1,90,C["srv"][1],13)
line([(900,fy2),(900,520),(1320,520),(1320,zy1)],C["atk"][1],3); arrow(1320,zy1,90,C["atk"][1],13)

# ---------- devices ----------
R=F("r",14); M=MONO(13)
card(85,660,475,870,C["cli"][1],"CLI-TI-01 · Windows 10",[
  ("10.0.1.101 (DHCP) · endpoint/vítima",R,MUTED),
  ("Sysmon · Universal Forwarder",R,INK),
  ("Microsoft Defender (AV)",R,INK),
  ("LimaCharlie EDR · planejado",F("m",14),"#7C3AED"),
  ("GPO: firewall 3 perfis · SMB-In",R,MUTED),
],("OU LAB\\Workstations","#1E4FA3","#D7E5FB"))

card(585,660,795,870,C["srv"][1],"DC01",[
  ("10.0.2.10",M,MUTED),
  ("Windows Server 2022",R,INK),
  ("AD DS · DNS",R,INK),
  ("meulab.local",M,MUTED),
  ("UF · planejado",F("m",14),"#7C3AED"),
])
card(810,660,1015,870,C["srv"][1],"Splunk",[
  ("10.0.2.20",M,MUTED),
  ("Ubuntu Server",R,INK),
  ("Splunk Enterprise · SIEM",R,INK),
  ("idx: windows",M,MUTED),
  ("     sysmon",M,MUTED),
  ("     pfsense_logs",M,MUTED),
])

card(1125,660,1515,800,C["atk"][1],"Kali Linux",[
  ("10.0.3.100 (DHCP) · origem dos ataques",R,MUTED),
  ("permitido: CLIENTS, DC01 (com log)",R,"#14774A"),
  ("bloqueado: Splunk, HOST, rede doméstica",R,"#B42318"),
])
text(1140,830,"Sem adaptador do HOST nas VMnets 2, 3 e 4:",F("m",13),MUTED)
text(1140,852,"o HOST só alcança o lab pela WAN.",F("r",13),MUTED)

# ---------- log flows ----------
# WIN10 -> Splunk (UF 9997): along bottom of zones
pts=[(280,870),(280,900),(912,900),(912,878)]
dline(pts,C["log"],3,10,6); arrow(912,876,270,C["log"],13)
pill(578,887,"Universal Forwarder · TCP 9997","#FFFFFF",C["log"],F("s",12))
# pfSense -> Splunk syslog
pts=[(1000,fy2),(1000,560),(1035,560),(1035,620),(980,620),(980,655)]
dline([(1010,430),(1060,430),(1060,620),(960,620),(960,656)],C["log"],3,10,6); arrow(960,658,90,C["log"],13)
pill(1068,404,"syslog · UDP 5140","#FFFFFF",C["log"],F("s",12))

# ---------- legend ----------
ly=975
text(60,ly,"Legenda",F("s",15))
def leg(x,kind,label):
    if kind=="log": dline([(x,ly+38),(x+46,ly+38)],C["log"],3,10,6); arrow(x+48,ly+38,0,C["log"])
    elif kind=="adm": line([(x,ly+38),(x+46,ly+38)],C["adm"],2); arrow(x+48,ly+38,0,C["adm"])
    elif kind=="net": line([(x,ly+38),(x+46,ly+38)],"#64748B",3); arrow(x+48,ly+38,0,"#64748B")
    elif kind=="plan": text(x,ly+38,"■",F("b",16),"#7C3AED","lm")
    text(x+62 if kind!="plan" else x+22,ly+38,label,F("r",14),INK,"lm")
leg(60,"net","interface roteada pelo pfSense")
leg(380,"log","envio de logs ao SIEM")
leg(660,"adm","acesso administrativo do analista")
leg(1010,"plan","componente planejado")
text(60,ly+80,"Splunk = SIEM · LimaCharlie = EDR · Defender = AV · Sysmon = telemetria · pfSense = firewall de rede · Active Directory = identidade",F("r",13),MUTED)

out=sys.argv[1]
img.save(out, optimize=True)
print("saved", out, img.size)
