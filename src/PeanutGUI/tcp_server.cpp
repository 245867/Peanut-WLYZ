// ============================================================
// Peanut WLYZ — TCP Server + Firewall  v7.0
// ============================================================

#include "tcp_server.h"

#include <httplib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windowsx.h>
#include <commctrl.h>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <fstream>
#include <thread>
#include <algorithm>

#include <nlohmann/json.hpp>
#include <wy_cipher.h>
#include <wy_hash.h>
#include <wy_random.h>
#include <wy_rsa.h>
#include <key_files.h>
#include <util.h>


// ============================================================
//  HTTP 服务端
// ============================================================
namespace {
    using SvrJson = nlohmann::ordered_json;
    using namespace peanut::psp;

    static std::vector<uint8_t> HexToBytes(const std::string& hex) {
        std::vector<uint8_t> out;
        for (size_t i = 0; i + 1 < hex.size(); i += 2)
            out.push_back((uint8_t)strtol(hex.substr(i, 2).c_str(), nullptr, 16));
        return out;
    }
    static std::string BytesToHex(const uint8_t* d, size_t n) {
        std::ostringstream ss; ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < n; ++i) ss << std::setw(2) << (int)d[i];
        return ss.str();
    }

    static std::string SvrEncryptB64(const std::string& plain, const std::string& key_hex) {
        auto key = HexToBytes(key_hex);
        if (key.size() < wy::WY_CIPHER_KEY_SIZE) return "";
        wy::wy_cipher_key ck; wy::wy_cipher_key_schedule(key.data(), &ck);
        uint8_t iv[16]; wy::wy_random_bytes(iv, 16);
        auto ct = wy::wy_cbc_encrypt(&ck, iv, (const uint8_t*)plain.data(), plain.size());
        std::vector<uint8_t> packed;
        packed.insert(packed.end(), iv, iv + 16);
        packed.insert(packed.end(), ct.begin(), ct.end());
        return Base64Encode(packed);
    }

    static std::string SvrDecryptB64(const std::string& b64, const std::string& key_hex) {
        auto raw = Base64Decode(b64);
        if (raw.size() < 16 + wy::WY_CIPHER_BLOCK_SIZE) return {};
        auto key = HexToBytes(key_hex);
        if (key.size() < wy::WY_CIPHER_KEY_SIZE) return {};
        wy::wy_cipher_key ck; wy::wy_cipher_key_schedule(key.data(), &ck);
        auto pt = wy::wy_cbc_decrypt(&ck, raw.data(), raw.data() + 16, raw.size() - 16);
        return std::string(pt.begin(), pt.end());
    }

    static std::string SvrHmacHex(const std::string& data, const std::string& key) {
        uint8_t out[wy::WY_HASH_OUTPUT_SIZE];
        wy::wy_hmac((const uint8_t*)key.data(), key.size(),
                     (const uint8_t*)data.data(), data.size(), out);
        return BytesToHex(out, wy::WY_HASH_OUTPUT_SIZE);
    }

    static std::string SvrSignJson(const SvrJson& j, const std::string& hmac_key) {
        SvrJson cpy = j;
        cpy.erase("signature");
        return SvrHmacHex(cpy.dump(), hmac_key);
    }

    static bool SvrParsePspFrame(const uint8_t* data, size_t len,
        PspHeader& hdr,
        std::vector<uint8_t>& rsa_block,
        std::array<uint8_t, PSP_IV_SIZE>& iv,
        std::vector<uint8_t>& ct,
        std::array<uint8_t, PSP_HASH_SIZE>& hmac)
    {
        if (len < PSP_MIN_FRAME) return false;
        size_t off = 0;
        memcpy(&hdr, data + off, PSP_HEADER_SIZE); off += PSP_HEADER_SIZE;
        if (hdr.magic0 != PSP_MAGIC0 || hdr.magic1 != PSP_MAGIC1) return false;
        if (hdr.version != PSP_VERSION) return false;
        rsa_block.assign(data + off, data + off + PSP_RSA_BLOCK); off += PSP_RSA_BLOCK;
        memcpy(iv.data(), data + off, PSP_IV_SIZE); off += PSP_IV_SIZE;
        size_t expected_ct = hdr.payload_len > PSP_IV_SIZE ? hdr.payload_len - PSP_IV_SIZE : 0;
        if (off + expected_ct + PSP_HASH_SIZE > len) return false;
        ct.assign(data + off, data + off + expected_ct); off += ct.size();
        memcpy(hmac.data(), data + off, PSP_HASH_SIZE);
        return true;
    }
}

// ═══════════════════════════════════════════════════════════
//  防火墙
// ═══════════════════════════════════════════════════════════
bool MainWindow::CheckFirewall(const std::string& ip, std::string& out_msg) {
    std::lock_guard<std::mutex> lock(firewallMutex_);
    auto it = firewall_.find(ip);
    if (it == firewall_.end()) return true;

    FwEntry& e = it->second;
    time_t now = time(nullptr);

    // 封禁中
    if (e.banUntil > now) {
        int remain = static_cast<int>(e.banUntil - now);
        char buf[128];
        snprintf(buf, sizeof(buf), "IP 已被临时封禁，请等待 %d 分钟后重试", (remain + 59) / 60);
        out_msg = buf;
        return false;
    }

    // 窗口过期，重置
    if (now - e.windowStart > config_.fw_window_minutes * 60) {
        e.failures = 0;
        e.windowStart = now;
    }
    return true;
}

void MainWindow::RecordFirewallFail(const std::string& ip) {
    std::lock_guard<std::mutex> lock(firewallMutex_);
    time_t now = time(nullptr);
    FwEntry& e = firewall_[ip];
    if (now - e.windowStart > config_.fw_window_minutes * 60) {
        e.failures = 0;
        e.windowStart = now;
    }
    e.failures++;
    if (e.failures >= config_.fw_max_attempts) {
        e.banUntil = now + config_.fw_ban_minutes * 60;
        {
            char buf[256];
            snprintf(buf, sizeof(buf), "[防火墙] IP %s 触发封禁 (%d 次/%d 分钟)",
                ip.c_str(), config_.fw_max_attempts, config_.fw_window_minutes);
            Log(buf, peanut_theme::ERROR_COLOR);
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  卡密解绑限制
// ═══════════════════════════════════════════════════════════
bool MainWindow::CheckUnbindLimit(const std::string& cardkey, std::string& out_msg) {
    if (!config_.unbind_enabled) { out_msg = "服务器未启用解绑功能"; return false; }
    time_t now = time(nullptr);
    struct tm nowTm;
    localtime_s(&nowTm, &now);
    char dateBuf[16];
    snprintf(dateBuf, sizeof(dateBuf), "%04d-%02d", nowTm.tm_year + 1900, nowTm.tm_mon + 1);
    std::string month(dateBuf);
    snprintf(dateBuf, sizeof(dateBuf), "%04d-%02d-%02d", nowTm.tm_year + 1900, nowTm.tm_mon + 1, nowTm.tm_mday);
    std::string day(dateBuf);

    auto& log = unbindLog_[cardkey];
    int dayCount = 0, monthCount = 0;
    for (auto& r : log) {
        if (r.date == day) dayCount += r.count;
        if (r.date.substr(0, 7) == month) monthCount += r.count;
    }
    if (dayCount >= config_.unbind_limit_day) {
        out_msg = "该卡密今日解绑次数已达上限";
        return false;
    }
    if (monthCount >= config_.unbind_limit_month) {
        out_msg = "该卡密本月解绑次数已达上限";
        return false;
    }
    return true;
}

void MainWindow::RecordUnbind(const std::string& cardkey) {
    time_t now = time(nullptr);
    struct tm nowTm;
    localtime_s(&nowTm, &now);
    char dateBuf[16];
    snprintf(dateBuf, sizeof(dateBuf), "%04d-%02d-%02d", nowTm.tm_year + 1900, nowTm.tm_mon + 1, nowTm.tm_mday);
    std::string day(dateBuf);

    auto& log = unbindLog_[cardkey];
    bool found = false;
    for (auto& r : log) {
        if (r.date == day) { r.count++; found = true; break; }
    }
    if (!found) log.push_back({day, 1});
}

bool MainWindow::RegisterServerSession(const std::string& token,
                                       const ServerSession& session,
                                       std::string& rejection) {
    std::lock_guard<std::mutex> lock(serverSessionsMutex_);
    const time_t now = time(nullptr);

    // 清理已经到期的会话，避免其占用并发名额。
    for (auto it = serverSessions_.begin(); it != serverSessions_.end();) {
        if (it->second.expires_at <= now)
            it = serverSessions_.erase(it);
        else
            ++it;
    }

    if (!config_.multi_open_enabled) {
        // 禁止多开：新登录是权威会话，同卡旧 token 全部立即失效。
        for (auto it = serverSessions_.begin(); it != serverSessions_.end();) {
            if (it->second.cardkey == session.cardkey)
                it = serverSessions_.erase(it);
            else
                ++it;
        }
    } else {
        const int limit = (std::max)(1, config_.max_online_per_card);
        int online = 0;
        for (const auto& item : serverSessions_) {
            if (item.second.cardkey == session.cardkey && item.second.expires_at > now)
                ++online;
        }
        if (online >= limit) {
            rejection = "该卡密在线数量已达到服务端限制（最多 " +
                        std::to_string(limit) + " 个）";
            return false;
        }
    }

    serverSessions_[token] = session;
    return true;
}

void MainWindow::StartServer() {
    if (serverRunning_) return;
    if (config_.port <= 0 || config_.port > 65535) {
        LogError("[服务端] 端口配置无效: " + std::to_string(config_.port));
        return;
    }

    std::string cipher_hex, hmac_key;
    peanut::keys::EnsureBusinessKeys("keys");
    if(!peanut::keys::LoadCipherKeyHex("keys",cipher_hex)||!peanut::keys::LoadHmacKey("keys",hmac_key)){LogError("[TCP] 无法加载 keys 业务密钥");return;}
    config_.aes_key_hex=cipher_hex;config_.hmac_key=hmac_key;
    int port = config_.port;
    MainWindow* self = this;
    WSADATA wd{};if(WSAStartup(MAKEWORD(2,2),&wd)!=0){LogError("[TCP] WSAStartup 失败");return;}
    SOCKET ls=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);BOOL yes=TRUE;setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,(char*)&yes,sizeof(yes));
    sockaddr_in addr{};addr.sin_family=AF_INET;addr.sin_addr.s_addr=INADDR_ANY;addr.sin_port=htons((u_short)port);
    if(ls==INVALID_SOCKET||bind(ls,(sockaddr*)&addr,sizeof(addr))!=0||listen(ls,SOMAXCONN)!=0){if(ls!=INVALID_SOCKET)closesocket(ls);WSACleanup();LogError("[TCP] 端口监听失败: "+std::to_string(port));return;}
    tcpListenSocket_=static_cast<uintptr_t>(ls);tcpServerRunning_=true;serverRunning_=true;
    LogSuccess("[TCP] 加密服务正在监听 0.0.0.0:"+std::to_string(port));
    std::thread([self,ls,cipher_hex,hmac_key](){
      auto response=[&](SvrJson r){r["signature"]=SvrSignJson(r,hmac_key);return SvrEncryptB64(r.dump(),cipher_hex);};
      while(self->tcpServerRunning_){sockaddr_in peer{};int peerLen=sizeof(peer);SOCKET c=accept(ls,(sockaddr*)&peer,&peerLen);if(c==INVALID_SOCKET){if(!self->tcpServerRunning_)break;continue;}char peerBuf[64]{};inet_ntop(AF_INET,&peer.sin_addr,peerBuf,sizeof(peerBuf));std::string peerIp=peerBuf;
       std::thread([self,c,cipher_hex,hmac_key,response,peerIp]() mutable {
        const uintptr_t connectionId = static_cast<uintptr_t>(c);
        auto recvAll=[&](char*p,size_t n){while(n){int x=recv(c,p,(int)n,0);if(x<=0)return false;p+=x;n-=x;}return true;};
        auto sendAll=[&](const char*p,size_t n){while(n){int x=send(c,p,(int)n,0);if(x<=0)return false;p+=x;n-=x;}return true;};
        while(self->tcpServerRunning_){uint32_t n=0;if(!recvAll((char*)&n,4))break;n=ntohl(n);if(!n||n>64*1024*1024)break;std::string wire(n,'\0');if(!recvAll(wire.data(),n))break;std::string out;
         try{SvrJson frame=SvrJson::parse(wire);std::string path=frame.value("path",""),enc=frame.value("data","");
          if(path=="/psp_handshake")out="ok";else{std::string plain=SvrDecryptB64(enc,cipher_hex);SvrJson q=SvrJson::parse(plain);std::string sig=q.value("signature","");q.erase("signature");
           if(sig.empty()||SvrHmacHex(q.dump(),hmac_key)!=sig)out=response({{"status","error"},{"message","请求签名校验失败"}});
           else if(path=="/update_policy")out=response({{"status","success"},{"force_update",self->config_.force_update_enabled},{"build_revoked",false},{"latest_version",self->config_.update_latest_version},{"minimum_version",self->config_.update_minimum_version},{"target_file",self->config_.update_target_file},{"target_sha256",self->config_.update_target_sha256},{"package_id",self->config_.update_package_id},{"package_sha256",self->config_.update_package_sha256},{"package_size",self->config_.update_package_size},{"manifest_version",1}});
           else if(path=="/update_download"){std::ifstream f(self->config_.update_package_path,std::ios::binary);std::vector<uint8_t>b((std::istreambuf_iterator<char>(f)),{});out=response({{"status",b.empty()?"error":"success"},{"package_data",Base64Encode(b)}});}
           else if(path=="/config_info")out=response({{"status","success"},{"announcement","Peanut TCP 服务运行中"},{"version","2.1.0"},{"multi_open_enabled",self->config_.multi_open_enabled},{"max_online_per_card",self->config_.multi_open_enabled?self->config_.max_online_per_card:1}});
           else if(path=="/auth_activate"){SvrJson r;std::string card=q.value("cardkey",""),machine=q.value("machinecode","");self->Log("[登录尝试] 卡密="+card+" IP="+peerIp);std::lock_guard<std::mutex> lock(self->cardsMutex_);bool found=false;for(auto& x:self->cards_)if(x.cardkey==card){found=true;if(x.status==3){r={{"status","error"},{"message","该卡密已被服务端禁用，请联系管理员"}};self->LogError("[登录失败] 卡密="+card+" IP="+peerIp+" 原因=卡密已禁用");break;}if(x.status==2){r={{"status","error"},{"message","该卡密授权已经过期，请续费或更换卡密"}};self->LogError("[登录失败] 卡密="+card+" IP="+peerIp+" 原因=授权已过期");break;}if(x.status==1&&!x.machine_code.empty()&&x.machine_code!=machine){r={{"status","error"},{"message","该卡密已绑定另一台电脑；当前设备与服务端绑定设备不一致，请在服务端解绑后重试"}};self->LogError("[登录失败] 卡密="+card+" IP="+peerIp+" 原因=设备绑定不一致");break;}time_t now=time(nullptr),expire=0;long long ttl=0;bool first=x.status==0||x.expire_time.empty();if(first){ttl=x.duration_type==4?999LL*365*86400:(x.duration_type==1?x.duration_value*3600LL:x.duration_type==2?x.duration_value*30LL*86400:x.duration_type==3?x.duration_value*365LL*86400:x.duration_value*86400LL);expire=now+ttl;char buf[64]{};tm local{};localtime_s(&local,&now);strftime(buf,sizeof(buf),"%Y-%m-%d %H:%M:%S",&local);x.activate_time=buf;localtime_s(&local,&expire);strftime(buf,sizeof(buf),"%Y-%m-%d %H:%M:%S",&local);x.expire_time=buf;}else{tm parsed{};std::istringstream ss(x.expire_time);ss>>std::get_time(&parsed,"%Y-%m-%d %H:%M:%S");expire=mktime(&parsed);ttl=expire-now;if(ttl<=0){x.status=2;self->SaveCards();r={{"status","error"},{"message","该卡密授权已经过期，请续费或更换卡密"}};self->LogError("[登录失败] 卡密="+card+" IP="+peerIp+" 原因=授权已到期");break;}}x.status=1;x.machine_code=machine;self->SaveCards();uint8_t rnd[32];wy::wy_random_bytes(rnd,32);std::string token=SvrHmacHex(card+machine+BytesToHex(rnd,32),hmac_key);std::string sessionReject;if(!self->RegisterServerSession(token,{card,machine,expire,now},sessionReject)){r={{"status","error"},{"message",sessionReject}};self->LogWarning("[会话拒绝] 卡密="+card+" 原因="+sessionReject);break;}r={{"status","success"},{"token",token},{"remaining_seconds",ttl},{"device_id",machine}};long long days=ttl/86400,hours=(ttl%86400)/3600,minutes=(ttl%3600)/60;std::string remaining=std::to_string(days)+"天";if(hours>0||days==0)remaining+=std::to_string(hours)+"小时";if(days==0&&(minutes>0||hours==0))remaining+=std::to_string(minutes)+"分钟";self->LogSuccess("[登录成功] 卡密="+card+" IP="+peerIp+" 类型="+(first?"首次激活":"同机二次登录")+" 剩余="+remaining);PostMessageW(self->hwndMain_,WM_APP+10,0,0);break;}if(!found){r={{"status","error"},{"message","卡密不存在，请检查是否输入错误、包含空格或使用了已删除的卡密"}};self->LogError("[登录失败] 卡密="+card+" IP="+peerIp+" 原因=卡密不存在");}out=response(r);}
           else{MainWindow::ServerSession s;{std::lock_guard<std::mutex> sl(self->serverSessionsMutex_);auto it=self->serverSessions_.find(q.value("token",""));if(it!=self->serverSessions_.end()&&(it->second.tcp_connection==0||it->second.tcp_connection==connectionId))s=it->second;}if(s.cardkey.empty()||s.expires_at<=time(nullptr))out=response({{"status","error"},{"message","登录会话无效、连接已断开或授权已过期，请重新登录"}});
             else if(path=="/auth_heartbeat"){{std::lock_guard<std::mutex> sl(self->serverSessionsMutex_);auto it=self->serverSessions_.find(q.value("token",""));if(it!=self->serverSessions_.end()){it->second.last_heartbeat=time(nullptr);it->second.tcp_connection=connectionId;}}out=response({{"status","success"},{"card_status","active"},{"usage_minutes",0},{"remaining_seconds",s.expires_at-time(nullptr)},{"request_nonce",q.value("nonce","")}});}
            else if(path=="/deactivate"){std::string card=q.value("cardkey","");bool reset=false;{std::lock_guard<std::mutex> lock(self->cardsMutex_);for(auto& x:self->cards_)if(x.cardkey==card&&x.machine_code==s.machine_code){x.machine_code.clear();x.status=0;x.activate_time.clear();reset=true;self->SaveCards();break;}}if(reset){std::lock_guard<std::mutex> sl(self->serverSessionsMutex_);self->serverSessions_.erase(q.value("token",""));PostMessageW(self->hwndMain_,WM_APP+10,0,0);out=response({{"status","success"},{"message","卡密已解绑"}});}else out=response({{"status","error"},{"message","卡密解绑失败"}});}
            else if(path=="/plugin_list"){SvrJson a=SvrJson::array();for(auto&p:self->local_plugins_)a.push_back({{"name",p.name},{"description",p.description},{"version",p.version},{"menu_text",p.name},{"enabled",p.enabled}});out=response({{"status","success"},{"plugins",a}});}
            else if(path=="/plugin_exec"){SvrJson r={{"status","error"},{"message","云函数不存在或未启用"}};for(auto&p:self->local_plugins_)if(p.name==q.value("plugin_name","")&&p.exec){std::string input=q.value("input","{}");int len=0;char*data=nullptr;int rc=p.exec(input.c_str(),(int)input.size(),&len,&data);if(rc==0&&data){SvrJson cloud;try{cloud=SvrJson::parse(std::string(data,len));}catch(...){cloud["plugin_result"]=std::string(data,len);}cloud["cloud_factor"]=7;cloud["cloud_context"]=SvrHmacHex(s.cardkey+"|"+s.machine_code+"|"+q.value("nonce",""),hmac_key).substr(0,24);r={{"status","success"},{"result",cloud.dump()},{"request_nonce",q.value("nonce","")},{"device_id",s.machine_code}};p.call_count++;if(p.free)p.free(data);}break;}out=response(r);}
            else out=response({{"status","error"},{"message","服务端不支持该请求"}});}}
         }catch(...){out=response({{"status","error"},{"message","请求格式错误"}});}
         uint32_t rn=htonl((uint32_t)out.size());if(!sendAll((char*)&rn,4)||!sendAll(out.data(),out.size()))break;}
        bool removedSession=false;{std::lock_guard<std::mutex> sl(self->serverSessionsMutex_);for(auto it=self->serverSessions_.begin();it!=self->serverSessions_.end();){if(it->second.tcp_connection==connectionId){it=self->serverSessions_.erase(it);removedSession=true;}else ++it;}}
        if(removedSession)PostMessageW(self->hwndMain_,WM_APP+10,0,0);
        closesocket(c);}).detach();}
    }).detach();
    return;

    auto svr = std::make_shared<httplib::Server>();
    // HTTP安全边界：本服务只提供明确注册的API，绝不挂载或映射任何本地目录。
    svr->set_payload_max_length(256 * 1024);
    svr->set_read_timeout(8, 0);
    svr->set_write_timeout(15, 0);
    svr->set_keep_alive_max_count(20);
    svr->set_pre_routing_handler([self](const httplib::Request& req, httplib::Response& res) {
        static const std::vector<std::string> allowed={"/psp_handshake","/update_policy","/auth_activate","/auth_heartbeat","/deactivate","/plugin_list","/plugin_exec"};
        auto reject=[&](int code,const char* message){res.status=code;res.set_header("Cache-Control","no-store");res.set_header("X-Content-Type-Options","nosniff");res.set_content(SvrJson{{"status","error"},{"message",message}}.dump(),"application/json; charset=utf-8");self->RecordFirewallFail(req.remote_addr);return httplib::Server::HandlerResponse::Handled;};
        if(req.path.size()>96||req.target.size()>2048)return reject(414,"请求地址过长");
        std::string lower=req.target;std::transform(lower.begin(),lower.end(),lower.begin(),[](unsigned char c){return(char)std::tolower(c);});
        if(lower.find("..")!=std::string::npos||lower.find("%2e")!=std::string::npos||lower.find("%2f")!=std::string::npos||lower.find("%5c")!=std::string::npos||lower.find('\\')!=std::string::npos||lower.find('%')!=std::string::npos||lower.find('<')!=std::string::npos||lower.find('>')!=std::string::npos||lower.find(';')!=std::string::npos||lower.find("union select")!=std::string::npos||lower.find("<script")!=std::string::npos)return reject(403,"检测到非法请求");
        if(std::find(allowed.begin(),allowed.end(),req.path)==allowed.end())return reject(404,"接口不存在");
        if((req.path=="/psp_handshake"&&req.method!="POST")||(req.path!="/psp_handshake"&&req.method!="GET"))return reject(405,"请求方法不允许");
        auto ct=req.get_header_value("Content-Type");if(req.method=="POST"&&ct.find("application/x-www-form-urlencoded")==std::string::npos)return reject(415,"请求内容类型不支持");
        return httplib::Server::HandlerResponse::Unhandled;
    });
    svr->set_post_routing_handler([](const httplib::Request&,httplib::Response& res){res.set_header("Cache-Control","no-store");res.set_header("X-Content-Type-Options","nosniff");res.set_header("X-Frame-Options","DENY");res.set_header("Content-Security-Policy","default-src 'none'");});
    svr->set_error_handler([](const httplib::Request&,httplib::Response& res){if(res.status<400)res.status=404;res.set_content(SvrJson{{"status","error"},{"message","请求被安全策略拒绝"}}.dump(),"application/json; charset=utf-8");});

    // 尝试加载 RSA 私钥（仅用于 PSP 握手校验，栈溢出时自动放行）
    wy::wy_rsa_prikey rsa_pri;
    bool has_rsa = peanut::keys::LoadServerPrivkey("keys", rsa_pri);
    if (!has_rsa) self->Log("[服务端] 未加载 RSA 密钥，PSP 握手将放行");

    svr->Post("/psp_handshake", [self, has_rsa](const httplib::Request& req, httplib::Response& res) {
        std::string b64 = req.get_param_value("data");
        if (b64.empty() && req.body.find("data=") == 0)
            b64 = httplib::detail::decode_url(req.body.substr(5), true);
        auto raw = Base64Decode(b64);
        PspHeader hdr{};
        std::vector<uint8_t> rsa_block, ct;
        std::array<uint8_t, PSP_IV_SIZE> iv{};
        std::array<uint8_t, PSP_HASH_SIZE> hmac{};
        if (!SvrParsePspFrame(raw.data(), raw.size(), hdr, rsa_block, iv, ct, hmac)) {
            res.status = 400; res.set_content("bad frame", "text/plain"); return;
        }
        self->Log("[服务端] PSP 握手成功");
        res.status = 200; res.set_content("{\"status\":\"ok\"}", "application/json");
    });

    auto handle_encrypted = [self, cipher_hex, hmac_key](const httplib::Request& req, httplib::Response& res,
        const std::function<SvrJson(const SvrJson&)>& handler)
    {
        std::string enc = req.get_param_value("data");
        std::string plain = SvrDecryptB64(enc, cipher_hex);
        if (plain.empty()) { res.status = 400; res.set_content("decrypt fail", "text/plain"); return; }
        try {
            SvrJson reqj = SvrJson::parse(plain);
            if (reqj.contains("signature")) {
                std::string sig = reqj["signature"].get<std::string>();
                reqj.erase("signature");
                if (SvrHmacHex(reqj.dump(), hmac_key) != sig) {
                    res.status = 403; res.set_content("bad sig", "text/plain"); return;
                }
            }
            SvrJson resp = handler(reqj);
            resp["signature"] = SvrSignJson(resp, hmac_key);
            res.status = 200;
            res.set_content(SvrEncryptB64(resp.dump(), cipher_hex), "text/plain");
        } catch (const std::exception& e) {
            res.status = 500; res.set_content(e.what(), "text/plain");
        }
    };

    svr->Get("/update_policy", [self, handle_encrypted](const httplib::Request& req, httplib::Response& res) {
        handle_encrypted(req, res, [self](const SvrJson&) {
            SvrJson r; r["status"] = "success";
            r["force_update"] = self->config_.force_update_enabled;
            r["build_revoked"] = false;
            r["latest_version"] = self->config_.update_latest_version;
            r["minimum_version"] = self->config_.update_minimum_version;
            r["target_file"] = self->config_.update_target_file;
            r["target_sha256"] = self->config_.update_target_sha256;
            r["package_id"] = self->config_.update_package_id;
            r["package_sha256"] = self->config_.update_package_sha256;
            r["package_size"] = self->config_.update_package_size;
            r["manifest_version"] = 1; return r;
        });
    });

    svr->Get("/auth_activate", [self, handle_encrypted](const httplib::Request& req, httplib::Response& res) {
        // 防火墙检查
        std::string fw_msg;
        if (!self->CheckFirewall(req.remote_addr, fw_msg)) {
            handle_encrypted(req, res, [fw_msg](const SvrJson&) {
                SvrJson r; r["status"] = "error"; r["message"] = fw_msg; return r;
            });
            return;
        }
        handle_encrypted(req, res, [self, &req](const SvrJson& reqj) {
            SvrJson resp;
            std::string cardkey = reqj.value("cardkey", "");
            std::string machine = reqj.value("machine_code", reqj.value("machinecode", ""));
            if (cardkey.empty()) {
                self->RecordFirewallFail(req.remote_addr);
                resp["status"] = "error"; resp["message"] = "卡密不能为空"; return resp;
            }
            std::lock_guard<std::mutex> lock(self->cardsMutex_);
            for (auto& c : self->cards_) {
                if (c.cardkey == cardkey) {
                    if (c.status == 1 && c.machine_code != machine) {
                        self->RecordFirewallFail(req.remote_addr);
                        resp["status"] = "error"; resp["message"] = "该卡密已绑定其他电脑，请先在服务端解绑"; return resp;
                    }
                    if (c.status == 2 || c.status == 3) {
                        self->RecordFirewallFail(req.remote_addr);
                        resp["status"] = "error"; resp["message"] = "该卡密已过期或已被禁用"; return resp;
                    }
                    c.status = 1;
                    c.machine_code = machine;
                    char buf[64]; time_t now = time(nullptr), expiresAt = 0;
                    struct tm tm_now{};
                    long long total_seconds = 0;
                    if (!c.expire_time.empty()) {
                        std::istringstream expiryStream(c.expire_time);
                        expiryStream >> std::get_time(&tm_now, "%Y-%m-%d %H:%M:%S");
                        expiresAt = mktime(&tm_now);
                        total_seconds = expiresAt - now;
                        if (total_seconds <= 0) {
                            c.status = 2;
                            self->SaveCards();
                            resp["status"] = "error";
                            resp["message"] = "授权已经过期，请续费或更换卡密";
                            return resp;
                        }
                    } else {
                        if (c.duration_type == 4) total_seconds = 999LL * 365 * 86400;
                        else if (c.duration_type == 0) total_seconds = c.duration_value * 86400LL;
                        else if (c.duration_type == 1) total_seconds = c.duration_value * 3600LL;
                        else if (c.duration_type == 2) total_seconds = c.duration_value * 30LL * 86400;
                        else if (c.duration_type == 3) total_seconds = c.duration_value * 365LL * 86400;
                        expiresAt = now + total_seconds;
                        localtime_s(&tm_now, &now);
                        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_now);
                        c.activate_time = buf;
                        localtime_s(&tm_now, &expiresAt);
                        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_now);
                        c.expire_time = buf;
                    }
                    self->SaveCards();
                    PostMessageW(self->hwndMain_, WM_APP + 10, 0, 0);
                    uint8_t nonce[32]; wy::wy_random_bytes(nonce, sizeof(nonce));
                    std::string material(cardkey + "|" + machine + "|" + std::to_string(time(nullptr)));
                    material.append(reinterpret_cast<const char*>(nonce), sizeof(nonce));
                    std::string token = SvrHmacHex(material, self->config_.hmac_key);
                    time_t nowHeartbeat=time(nullptr);
                    std::string sessionReject;
                    if (!self->RegisterServerSession(token,
                            {cardkey, machine, expiresAt, nowHeartbeat},
                            sessionReject)) {
                        resp["status"] = "error";
                        resp["message"] = sessionReject;
                        self->LogWarning("[会话拒绝] 卡密=" + cardkey + " 原因=" + sessionReject);
                        return resp;
                    }
                    resp["status"] = "success"; resp["token"] = token; resp["remaining_seconds"] = total_seconds; resp["device_id"] = machine;
                    self->LogSuccess("[服务端] 卡密激活: " + cardkey);
                    return resp;
                }
            }
            self->RecordFirewallFail(req.remote_addr);
            resp["status"] = "error"; resp["message"] = "卡密不存在，请检查输入是否正确"; return resp;
        });
    });

    svr->Get("/auth_heartbeat", [self, handle_encrypted](const httplib::Request& req, httplib::Response& res) {
        std::string fw_msg;
        if (!self->CheckFirewall(req.remote_addr, fw_msg)) {
            handle_encrypted(req, res, [fw_msg](const SvrJson&) {
                SvrJson r; r["status"] = "error"; r["message"] = fw_msg; return r;
            });
            return;
        }
        handle_encrypted(req, res, [self, &req](const SvrJson& reqj) {
            SvrJson resp;
            std::string token = reqj.value("token", ""); ServerSession session;
            { std::lock_guard<std::mutex> sessionLock(self->serverSessionsMutex_); auto it=self->serverSessions_.find(token); if(it==self->serverSessions_.end()){self->RecordFirewallFail(req.remote_addr);resp["status"]="error";resp["message"]="登录会话无效或已过期，请重新登录";return resp;} session=it->second; }
            if (session.expires_at <= time(nullptr)) {
                self->RecordFirewallFail(req.remote_addr);
                resp["status"] = "error"; resp["message"] = "授权已经过期，请重新登录"; return resp;
            }
            std::lock_guard<std::mutex> lock(self->cardsMutex_);
            for (auto& c : self->cards_) {
                if (c.cardkey == session.cardkey && c.machine_code == session.machine_code) {
                    { std::lock_guard<std::mutex> sessionLock(self->serverSessionsMutex_); auto it=self->serverSessions_.find(token); if(it!=self->serverSessions_.end())it->second.last_heartbeat=time(nullptr); }
                    PostMessageW(self->hwndMain_, WM_APP + 10, 0, 0);
                    resp["status"] = "success";
                    resp["card_status"] = "active";
                    resp["usage_minutes"] = c.usage_count;
                    resp["remaining_seconds"] = session.expires_at - time(nullptr);
                    resp["request_nonce"] = reqj.value("nonce", "");
                    return resp;
                }
            }
            self->RecordFirewallFail(req.remote_addr);
            resp["status"] = "error"; resp["message"] = "卡密不存在或绑定关系已失效"; return resp;
        });
    });

    svr->Get("/deactivate", [self, handle_encrypted](const httplib::Request& req, httplib::Response& res) {
        handle_encrypted(req, res, [self, &req](const SvrJson& reqj) {
            SvrJson resp;
            std::string cardkey = reqj.value("cardkey", "");
            // 解绑限制检查
            std::string bind_msg;
            if (!self->CheckUnbindLimit(cardkey, bind_msg)) {
                resp["status"] = "error"; resp["message"] = bind_msg; return resp;
            }
            std::lock_guard<std::mutex> lock(self->cardsMutex_);
            for (auto& c : self->cards_) {
                if (c.cardkey == cardkey) {
                    c.machine_code.clear();
                    c.status = 0; // 重置为未激活
                    c.activate_time.clear();
                    { std::lock_guard<std::mutex> sessionLock(self->serverSessionsMutex_); for(auto it=self->serverSessions_.begin();it!=self->serverSessions_.end();){if(it->second.cardkey==cardkey)it=self->serverSessions_.erase(it);else ++it;} }
                    self->SaveCards();
                    PostMessageW(self->hwndMain_, WM_APP + 10, 0, 0);
                    self->RecordUnbind(cardkey);
                    self->LogSuccess("[服务端] 卡密解绑: " + cardkey);
                    resp["status"] = "success";
                    return resp;
                }
            }
            resp["status"] = "error"; resp["message"] = "卡密不存在，请检查输入是否正确"; return resp;
        });
    });

    svr->Get("/plugin_list", [self, handle_encrypted](const httplib::Request& req, httplib::Response& res) {
        handle_encrypted(req, res, [self](const SvrJson& reqj) {
            SvrJson resp; resp["status"] = "success";
            { std::lock_guard<std::mutex> lock(self->serverSessionsMutex_); if(self->serverSessions_.find(reqj.value("token",""))==self->serverSessions_.end()){resp["status"]="error";resp["message"]="登录会话无效或已过期，请重新登录";return resp;} }
            SvrJson arr = SvrJson::array();
            for (auto& plg : self->local_plugins_) {
                SvrJson item;
                item["name"] = plg.name;
                item["description"] = plg.description;
                item["version"] = plg.version;
                item["menu_text"] = plg.name;
                item["enabled"] = plg.enabled;
                item["call_count"] = plg.call_count;
                arr.push_back(std::move(item));
            }
            resp["plugins"] = arr;
            return resp;
        });
    });

    svr->Get("/plugin_exec", [self, handle_encrypted](const httplib::Request& req, httplib::Response& res) {
        handle_encrypted(req, res, [self](const SvrJson& reqj) {
            SvrJson resp;
            ServerSession session; { std::lock_guard<std::mutex> lock(self->serverSessionsMutex_); auto it=self->serverSessions_.find(reqj.value("token","")); if(it==self->serverSessions_.end()){resp["status"]="error";resp["message"]="登录会话无效或已过期，请重新登录";return resp;} session=it->second; }
            std::string name = reqj.value("plugin_name", "");
            std::string input = reqj.value("input", "{}");
            for (auto& plg : self->local_plugins_) {
                if (plg.name == name && plg.exec) {
                    plg.call_count++;
                    int outLen = 0; char* outData = nullptr;
                    int rc = plg.exec(input.c_str(), (int)input.size(), &outLen, &outData);
                    if (rc == 0 && outData) {
                        resp["status"] = "success";
                        resp["result"] = std::string(outData, outLen);
                        resp["call_count"] = plg.call_count;
                        resp["device_id"] = session.machine_code; resp["request_nonce"] = reqj.value("nonce", "");
                        if (plg.free) plg.free(outData);
                    } else {
                        resp["status"] = "error";
                        resp["message"] = "云函数执行失败";
                        resp["call_count"] = plg.call_count;
                        if (plg.free && outData) plg.free(outData);
                    }
                    return resp;
                }
            }
            resp["status"] = "error"; resp["message"] = "云函数不存在或未启用";
            return resp;
        });
    });

    httpServer_ = svr;
    serverRunning_ = true;
    LogSuccess("[服务端] 正在监听 0.0.0.0:" + std::to_string(port));

    std::thread([self, svr, port]() {
        svr->listen("0.0.0.0", port);
    }).detach();
}

void MainWindow::StopServer() {
    if (!serverRunning_) return;
    tcpServerRunning_=false;
    if(tcpListenSocket_!=static_cast<uintptr_t>(~0ULL)){closesocket(static_cast<SOCKET>(tcpListenSocket_));tcpListenSocket_=static_cast<uintptr_t>(~0ULL);WSACleanup();}
    if (httpServer_) {
        httpServer_->stop();
        httpServer_.reset();
    }
    serverRunning_ = false;
    Log("[服务端] 已停止");
}


