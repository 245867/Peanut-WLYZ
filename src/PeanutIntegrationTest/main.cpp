#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include "../PeanutClient/sdk/peanut_secure_client.h"
#include "../PeanutClient/sdk/security_runtime.h"

namespace fs = std::filesystem;
using peanut::sdk::PeanutSecureClient;

static std::ofstream g_log;
static int g_pass = 0, g_fail = 0;
static bool g_expect_force_update=false;
static void Log(const std::string& text) { std::cout << text << std::endl; g_log << text << std::endl; }
static void Check(bool ok, const std::string& name) { if(ok){++g_pass;Log("[PASS] "+name);}else{++g_fail;Log("[FAIL] "+name);} }

static bool RunClientFlow(const std::string& product, const std::string& card,
                          const std::string& machine, int port, std::string& out_token) {
    Log("--- " + product + " ---");
    PeanutSecureClient client;
    client.SetServer("127.0.0.1", port);
    client.SetTransportMode(peanut::sdk::TransportMode::TCP);
    client.SetCallbacks([](const std::string& m,int){Log("[SDK] "+m);});
    if(!client.LoadKeysFromDir("keys")) return false;
    Check(client.Connect(), product+" connect"); if(!client.IsConnected()) return false;
    peanut::sdk::UpdatePolicy update; std::string err;
    Check(client.FetchUpdatePolicy(product,"2.1.0","integration-build",update,&err),product+" update policy");
    Check(g_expect_force_update ? update.force_update : (!update.force_update && !update.build_revoked),product+(g_expect_force_update?" force update policy enabled":" update switch off allows run"));
    std::string announcement,version; Check(client.FetchConfigInfo(announcement,version),product+" config");
    Check(client.Activate(card,machine,out_token,&err),product+" activate"); if(out_token.empty()) return false;
    std::string status; int minutes=0; long long remaining=0;
    Check(client.SendHeartbeat(out_token,status,minutes,remaining),product+" heartbeat");
    Check(remaining>0,product+" remaining time");
    std::vector<CloudPluginInfo> plugins; Check(client.FetchPluginList(out_token,plugins,&err),product+" plugin list");
    Check(!plugins.empty(),product+" plugin list non-empty");
    std::string result; Check(client.CallPlugin(out_token,"echo","{\"source\":\""+product+"\"}",result,&err),product+" cloud DLL echo");
    auto cloud=nlohmann::json::parse(result); int local_value=5; int computed=local_value*cloud.value("cloud_factor",0);
    Check(computed==35,product+" cloud DLL parameter participates in real calculation");
    if (product == "client_demo1") {
        std::string vertical; Check(client.CallPlugin(out_token,"monitor_policy","{\"action\":\"vertical_scene\"}",vertical,&err),"monitor policy vertical cloud call");
        auto vp=nlohmann::json::parse(vertical); Check(vp.value("width",0)==540&&vp.value("height",0)==960&&vp.value("fps",0)==20,"vertical cloud parameters are usable");
        std::string loop; Check(client.CallPlugin(out_token,"monitor_policy","{\"action\":\"loop_live\"}",loop,&err),"monitor policy loop cloud call");
        auto lp=nlohmann::json::parse(loop); int requested=999; int effective=(std::min)((std::max)(requested,lp.value("min_minutes",0)),lp.value("max_minutes",0));
        Check(effective==240,"loop cloud policy participates in real calculation");
    }
    const std::string first_token=out_token;
    long long before_relogin=client.GetLastActivationRemainingSeconds();std::string relogin_token;
    Check(client.Activate(card,machine,relogin_token,&err),product+" same-device second login");
    long long after_relogin=client.GetLastActivationRemainingSeconds();
    Check(after_relogin>0&&after_relogin<=before_relogin+2,product+" second login keeps original expiry");
    std::string oldStatus;int oldMinutes=0;long long oldRemaining=0;
    Check(!client.SendHeartbeat(first_token,oldStatus,oldMinutes,oldRemaining),
          product+" second login revokes previous token");
    Check(client.SendHeartbeat(relogin_token,oldStatus,oldMinutes,oldRemaining),
          product+" newest token remains valid");
    if(!relogin_token.empty())out_token=relogin_token;
    client.Disconnect(); return true;
}

static void TestPluginDll(const fs::path& path, int expected_min_count) {
    HMODULE mod=LoadLibraryW(path.c_str()); Check(mod!=nullptr,path.filename().string()+" load"); if(!mod)return;
    auto exec=(int(*)(const char*,int,int*,char**))GetProcAddress(mod,"PluginExecute");
    auto freeFn=(void(*)(char*))GetProcAddress(mod,"PluginFree");
    auto count=(int(*)())GetProcAddress(mod,"PluginGetFunctionCount");
    Check(exec&&freeFn,path.filename().string()+" required exports");
    Check(count&&count()>=expected_min_count,path.filename().string()+" function count");
    if(exec&&freeFn){int len=0;char* data=nullptr;std::string file=path.filename().string();std::string input=file=="abogus.dll"?"{\"action\":\"secure_random\",\"length\":16}":file=="monitor_policy.dll"?"{\"action\":\"vertical_scene\"}":"{}";int rc=exec(input.c_str(),(int)input.size(),&len,&data);Check(rc==0&&data&&len>0,path.filename().string()+" execute");if(data)freeFn(data);}
    FreeLibrary(mod);
}

int main(int argc,char** argv) {
    SetConsoleOutputCP(CP_UTF8);
    wchar_t module[MAX_PATH] = {}; GetModuleFileNameW(nullptr, module, MAX_PATH);
    fs::current_path(fs::path(module).parent_path());
    fs::create_directories("logs"); g_log.open("logs/integration_test.log",std::ios::trunc);
    Log("Peanut pure C++ integration test");
    {
        peanut::security::AuthorizationGuard guard;
        Check(guard.BeginLogin(),"guard begins login");
        Check(!guard.CompleteLogin("token",0,"device"),"guard rejects zero TTL");
        Check(guard.BeginLogin(),"guard can retry after failed login");
        Check(!guard.CompleteLogin("token",-1,"device"),"guard rejects negative TTL");
        Check(guard.BeginLogin(),"guard begins short-TTL login");
        Check(guard.CompleteLogin("token",1,"device")&&guard.EnterRunning(),"guard enters running");
        Sleep(1200);
        Check(!guard.RequireAuthorized()&&guard.RemainingSeconds()==0,"guard locally expires TTL");
        guard.Invalidate(peanut::security::AuthorizationState::AUTH_EXPIRED);
        Check(guard.LastFailReason()==peanut::security::AuthorizationState::AUTH_EXPIRED,
              "guard preserves expiry reason after clear");
    }
    bool external=argc>1&&std::string(argv[1])=="--gui";g_expect_force_update=external&&argc>2&&std::string(argv[2])=="--update";int testPort=external?9001:9021;
    STARTUPINFOW si{sizeof(si)}; PROCESS_INFORMATION pi{};bool started=true;if(!external){wchar_t cmd[]=L"PeanutMockServer.exe 9021 keys";started=CreateProcessW(nullptr,cmd,nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi)!=FALSE;Check(started,"start mock server");if(!started)return 2;Sleep(1000);}
    std::string t1,t2,t3;
    std::string c1=external?"KD8E-BNYQ-USKT-T5KM":"IT-CARD-1",c2=external?"VG56-HN83-E8P6-GZH8":"IT-CARD-2",c3=external?"TK_KD8EBNYQUSKTT5KMVG56HN83E8P6G":"IT-CARD-3";
    Check(RunClientFlow("client_demo1",c1,"IT-DEVICE-1",testPort,t1),"client_demo1 full flow completed");
    Check(RunClientFlow("client_demo2",c2,"IT-DEVICE-2",testPort,t2),"client_demo2 full flow completed");
    Check(RunClientFlow("client_demo3",c3,"IT-DEVICE-3",testPort,t3),"client_demo3 full flow completed");

    PeanutSecureClient attacker; attacker.SetServer("127.0.0.1",testPort); attacker.SetTransportMode(peanut::sdk::TransportMode::TCP); attacker.LoadKeysFromDir("keys"); attacker.Connect();
    std::string badToken,err; Check(!attacker.Activate(c1,"OTHER-DEVICE",badToken,&err),"one card rejects another device");
    std::string s;int m=0;long long r=0;Check(!attacker.SendHeartbeat("invalid-token",s,m,r),"invalid token heartbeat rejected");
    std::string output;Check(!attacker.CallPlugin("invalid-token","echo","{}",output,&err),"invalid token cloud call rejected");
    if (external) {
        PeanutSecureClient cleanup; cleanup.SetServer("127.0.0.1",testPort); cleanup.SetTransportMode(peanut::sdk::TransportMode::TCP); cleanup.LoadKeysFromDir("keys"); cleanup.Connect();
        Check(cleanup.DeactivateCard(t1,c1),"cleanup client_demo1 test card");
        cleanup.Disconnect();
        PeanutSecureClient cleanup2; cleanup2.SetServer("127.0.0.1",testPort); cleanup2.SetTransportMode(peanut::sdk::TransportMode::TCP); cleanup2.LoadKeysFromDir("keys"); cleanup2.Connect();
        Check(cleanup2.DeactivateCard(t2,c2),"cleanup client_demo2 test card"); cleanup2.Disconnect();
        PeanutSecureClient cleanup3; cleanup3.SetServer("127.0.0.1",testPort); cleanup3.SetTransportMode(peanut::sdk::TransportMode::TCP); cleanup3.LoadKeysFromDir("keys"); cleanup3.Connect();
        Check(cleanup3.DeactivateCard(t3,c3),"cleanup client_demo3 test card"); cleanup3.Disconnect();
    }
    if(external&&argc>2&&std::string(argv[2])=="--update"){peanut::sdk::UpdatePolicy up;Check(attacker.FetchUpdatePolicy("update_probe","0.0.0","bad-build",up,&err),"force update policy fetch");Check(up.force_update,"force update switch enabled");std::vector<uint8_t>pkg;Check(attacker.DownloadUpdatePackage(up.package_id,pkg,&err),"encrypted TCP update download");Check(static_cast<long long>(pkg.size())==up.package_size,"update package size");fs::path probe="logs/update_probe.bin";{std::ofstream o(probe,std::ios::binary|std::ios::trunc);o.write((char*)pkg.data(),pkg.size());}Check(peanut::security::FileSha256Hex(probe.wstring())==up.package_sha256,"update package SHA-256");fs::remove(probe);}

    TestPluginDll("plugins/echo.dll",1); TestPluginDll("plugins/system_info_plugin.dll",1); TestPluginDll("plugins/abogus.dll",9); TestPluginDll("plugins/monitor_policy.dll",3);
    if(!external){TerminateProcess(pi.hProcess,0); WaitForSingleObject(pi.hProcess,3000); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);}
    Log("SUMMARY pass="+std::to_string(g_pass)+" fail="+std::to_string(g_fail));
    return g_fail==0?0:1;
}
