#include<stdio.h>
#include<stdlib.h>
char direct[78] = "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt";
char direct_CN[72] = "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt";
char proxy[77] = "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt";
char proxy_CN[71] = "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt";
char reject[78] = "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt";
char reject_CN[72] = "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt";
char apple[77] = "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/apple.txt";
char apple_CN[71] = "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/apple.txt";
char icloud[78] = "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/icloud.txt";
char icloud_CN[72] = "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/icloud.txt";
char google[78] = "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/google.txt";
char google_CN[72] = "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/google.txt";
char lancidr[79] = "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/lancidr.txt";
char lancidr_CN[73] = "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt";
char cncidr[78] = "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/cncidr.txt";
char cncidr_CN[72] = "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt";//_CN为Cloudflare CDN托管,raw部分网络无法访问

int mode, cdn;
char server_name[30];
FILE* yaml;

int preload() {
	yaml = fopen("clash.yaml", "w");
	fprintf(yaml, "port: 7890\nsocks-port: 7891\nallow-lan: true\nmode: rule\nlog-level: info\nipv6: true\nexternal-controller: 127.0.0.1:9090\n");
	fclose(yaml);
	return 0;
}

int ui() {
	printf("------------------------------------------\n");
	printf("----------------Clash规则转换-------------\n");
	printf("------------------------------------------\n");
	printf("1.V2ray转Clash(仅支持ws+tls)\n\n2.Trojan转Clash(不支持Trojan-Go)\n\n3.Snell转Clash(仅支持tls混淆)\n\n4.Mixin模式参数生成\n\n5.删除Clash日志文件\n");
	printf("------------------------------------------\n");
	printf("请选择:");
	scanf("%d", &mode);
	return 0;
}

int main() {
	preload();
	ui();
	system("cls");
	if (mode == 1) {
		VmessToClash();
		general();
		system("cls");
		printf("Clash配置已保存于Clash.yaml\n");
		system("notepad clash.yaml");
	}
	else if (mode == 2) {
		TrojanToClash();
		general();
		system("cls");
		printf("Clash配置已保存于Clash.yaml\n");
		system("notepad clash.yaml");
	}
	else if (mode == 3) {
		SnellToClash();
		general();
		system("cls");
		printf("Clash配置已保存于Clash.yaml\n");
		system("notepad clash.yaml");
	}
	else if (mode == 4) {
		MixinToClash();
		system("cls");
		printf("Mixin配置已保存于Mixin.yaml\n");
		system("notepad Mixin.yaml");
	}
	else if (mode == 5) {
		system("del /F /S /Q %USERPROFILE%\\.config\\clash\\logs\\*");
		printf("Clash日志文件已清理!\n");
		system("explorer %USERPROFILE%\\.config\\clash\\logs\\");
	}
	return 0;
}

int SnellToClash() {
	char ip[50], psk[50];
	printf("请输入节点名称:");
	scanf("%s", server_name);
	printf("\n请输入服务器绑定的域名或ip地址:");
	scanf("%s", ip);
	printf("\n请输入密码:");
	scanf("%s", psk);
	yaml = fopen("clash.yaml", "a");
	fprintf(yaml, "proxies:\n");
	fprintf(yaml, "  - {name: %s, server: %s, port: 443, type: snell, psk: %s, obfs-opts: {mode: tls}}\n", server_name, ip, psk);
	fclose(yaml);
	return 0;
}

int TrojanToClash() {
	char domain_name[50],pw[50];
	printf("请输入节点名称:");
	scanf("%s", server_name);
	printf("\n请输入服务器绑定的域名:");
	scanf("%s", domain_name);
	printf("\n请输入密码:");
	scanf("%s", pw);
	yaml = fopen("clash.yaml", "a");
	fprintf(yaml, "proxies:\n");
	fprintf(yaml, "  - {name: %s, server: %s, port: 443, type: trojan, password: %s, udp: true}\n", server_name,domain_name, pw);
	fclose(yaml);
	return 0;
}

int VmessToClash() {
	char domain_name[50], uuid[40], ws_path[10],cdn_domain_name[50];
	int alterld;
	printf("请输入节点名称:");
	scanf("%s", server_name);
	printf("\n请输入服务器绑定的域名:");
	scanf("%s", domain_name);
	printf("\n请输入uuid:");
	scanf("%s", uuid);
	printf("\n请输入alterld:");
	scanf("%d", &alterld);
	printf("\n请输入websocket路径，带/:");
	scanf("%s", ws_path);
	printf("\n请输入CDN服务器域名或ip，没有嵌套CDN请输入@:");
	scanf("%s", cdn_domain_name);
	if (cdn_domain_name[0] == '@') {
		sprintf(cdn_domain_name, "%s", domain_name);
	}
	yaml = fopen("clash.yaml", "a");
	fprintf(yaml,"proxies:\n");
	fprintf(yaml, "  - {name: %s, server: %s, port: 443, type: vmess, uuid: %s, alterId: %d, cipher: auto, tls: true, network: ws, ws-path: %s, ws-headers: {Host: %s}, udp: true}\n",domain_name,cdn_domain_name,uuid,alterld,ws_path,domain_name);
	fclose(yaml);
	return 0;
}

int MixinToClash() {
	char dns1[50], dns2[50];
	printf("支持Tcp查询、非标准端口查询、DNS Over TLS与DNS Over Https:\n");
	printf("\n请输入首选DNS服务器(如tls://101.101.101.101):");
	scanf("%s", dns1);
	printf("\n请输入备用DNS服务器:");
	scanf("%s", dns2);
	yaml = fopen("Mixin.yaml", "w");
	fprintf(yaml, " mixin:\n");
	fprintf(yaml, "   dns:\n");
	fprintf(yaml, "     enable: true\n");
	fprintf(yaml, "     listen: :53\n");
	fprintf(yaml, "     nameserver:\n");
	fprintf(yaml, "       - %s\n",dns1);
	fprintf(yaml, "       - %s\n", dns2);
	fclose(yaml);
	return 0;
}

int general() {
	printf("\n请选择CDN:\n\n1.Cloudflare(稳定,更新慢12h)\n\n2.Github(更新快，部分网络无法访问)\n\n请选择:");
	scanf("%d", &cdn);
	yaml = fopen("clash.yaml", "a");
	fprintf(yaml, "proxy-groups:\n");
	fprintf(yaml, "  - name: \"PROXY\"\n");
	fprintf(yaml, "    type: select\n");
	fprintf(yaml, "    proxies:\n");
	fprintf(yaml, "      - Fallback\n");
	fprintf(yaml, "      - %s\n", server_name);
	fprintf(yaml, "  - name: \"Fallback\"\n");
	fprintf(yaml, "    type: fallback\n");
	fprintf(yaml, "    proxies:\n");
	fprintf(yaml, "      - %s\n", server_name);
	fprintf(yaml, "    url: 'http://www.gstatic.com/generate_204'\n");
	fprintf(yaml, "    interval: 300\n");
	fprintf(yaml, "rule-providers:\n");
	fprintf(yaml, "  reject:\n");
	fprintf(yaml, "    type: http\n");
	fprintf(yaml, "    behavior: domain\n");
	if (cdn == 2) {
		fprintf(yaml, "    url: \"%s\"\n", reject);
	}
	else {
		fprintf(yaml, "    url: \"%s\"\n", reject_CN);
	}
	fprintf(yaml, "    path: ./ruleset/reject.yaml\n");
	fprintf(yaml, "    interval: 86400\n");
	fprintf(yaml, "  icloud:\n");
	fprintf(yaml, "    type: http\n");
	fprintf(yaml, "    behavior: domain\n");
	if (cdn == 2) {
		fprintf(yaml, "    url: \"%s\"\n", icloud);
	}
	else {
		fprintf(yaml, "    url: \"%s\"\n", icloud_CN);
	}
	fprintf(yaml, "    path: ./ruleset/icloud.yaml\n");
	fprintf(yaml, "    interval: 86400\n");
	fprintf(yaml, "  apple:\n");
	fprintf(yaml, "    type: http\n");
	fprintf(yaml, "    behavior: domain\n");
	if (cdn == 2) {
		fprintf(yaml, "    url: \"%s\"\n", apple);
	}
	else {
		fprintf(yaml, "    url: \"%s\"\n", apple_CN);
	}
	fprintf(yaml, "    path: ./ruleset/apple.yaml\n");
	fprintf(yaml, "    interval: 86400\n");
	fprintf(yaml, "  google:\n");
	fprintf(yaml, "    type: http\n");
	fprintf(yaml, "    behavior: domain\n");
	if (cdn == 2) {
		fprintf(yaml, "    url: \"%s\"\n", google);
	}
	else {
		fprintf(yaml, "    url: \"%s\"\n", google_CN);
	}
	fprintf(yaml, "    path: ./ruleset/google.yaml\n");
	fprintf(yaml, "    interval: 86400\n");
	fprintf(yaml, "  proxy:\n");
	fprintf(yaml, "    type: http\n");
	fprintf(yaml, "    behavior: domain\n");
	if (cdn == 2) {
		fprintf(yaml, "    url: \"%s\"\n", proxy);
	}
	else {
		fprintf(yaml, "    url: \"%s\"\n", proxy_CN);
	}
	fprintf(yaml, "    path: ./ruleset/proxy.yaml\n");
	fprintf(yaml, "    interval: 86400\n");
	fprintf(yaml, "  direct:\n");
	fprintf(yaml, "    type: http\n");
	fprintf(yaml, "    behavior: domain\n");
	if (cdn == 2) {
		fprintf(yaml, "    url: \"%s\"\n", direct);
	}
	else {
		fprintf(yaml, "    url: \"%s\"\n", direct_CN);
	}
	fprintf(yaml, "    path: ./ruleset/direct.yaml\n");
	fprintf(yaml, "    interval: 86400\n");
	fprintf(yaml, "  cncidr:\n");
	fprintf(yaml, "    type: http\n");
	fprintf(yaml, "    behavior: ipcidr\n");
	if (cdn == 2) {
		fprintf(yaml, "    url: \"%s\"\n", cncidr);
	}
	else {
		fprintf(yaml, "    url: \"%s\"\n", cncidr_CN);
	}
	fprintf(yaml, "    path: ./ruleset/cncidr.yaml\n");
	fprintf(yaml, "    interval: 86400\n");
	fprintf(yaml, "  lancidr:\n");
	fprintf(yaml, "    type: http\n");
	fprintf(yaml, "    behavior: ipcidr\n");
	if (cdn == 2) {
		fprintf(yaml, "    url: \"%s\"\n", lancidr);
	}
	else {
		fprintf(yaml, "    url: \"%s\"\n", lancidr_CN);
	}
	fprintf(yaml, "    path: ./ruleset/lancidr.yaml\n");
	fprintf(yaml, "    interval: 86400\n");
	fprintf(yaml, "rules:\n");
	fprintf(yaml, "  - PROCESS-NAME,qq,DIRECT\n");
	fprintf(yaml, "  - PROCESS-NAME,wechat,DIRECT\n");
	fprintf(yaml, "  - PROCESS-NAME,baidunetdisk,DIRECT\n");
	fprintf(yaml, "  - PROCESS-NAME,baidunetdiskhost,DIRECT\n");
	fprintf(yaml, "  - PROCESS-NAME,HiSuite,DIRECT\n");
	fprintf(yaml, "  - PROCESS-NAME,xunyou,DIRECT\n");
	fprintf(yaml, "  - RULE-SET,reject,REJECT\n");
	fprintf(yaml, "  - RULE-SET,icloud,DIRECT\n");
	fprintf(yaml, "  - RULE-SET,apple,DIRECT\n");
	fprintf(yaml, "  - RULE-SET,google,PROXY\n");
	fprintf(yaml, "  - RULE-SET,proxy,PROXY\n");
	fprintf(yaml, "  - RULE-SET,direct,DIRECT\n");
	fprintf(yaml, "  - RULE-SET,lancidr,DIRECT,no-resolve\n");
	fprintf(yaml, "  - RULE-SET,cncidr,DIRECT,no-resolve\n");
	fprintf(yaml, "  - GEOIP,CN,DIRECT\n");
	fprintf(yaml, "  - MATCH,PROXY\n");
	fclose(yaml);
	return 0;
}
