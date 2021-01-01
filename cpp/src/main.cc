#include <cpr/cpr.h>
#include <ctime>
#include <iostream>
#include <map>
#include <regex>
#include <string>
#include <vector>
#include <algorithm>

#include "base64.h"
#include "hmac.h"
#include "md5.h"
#include "sha1.h"

#define __DEBUG

using namespace std;

const int ordat(string const &msg, size_t idx) { // Test OK
  if (msg.size() > idx)
    return static_cast<int>(msg.at(idx));
  return 0;
}

const vector<int> sencode(string const &msg, bool key) { // Test OK
  int l = msg.size();
  vector<int> pwd;
  for (int i = 0; i < l; i += 4)
    pwd.push_back(ordat(msg, i) | ordat(msg, i + 1) << 8 |
                  ordat(msg, i + 2) << 16 | ordat(msg, i + 3) << 24);
  if (key)
    pwd.push_back(l);
  return pwd;
}

const string lencode(vector<int> &msg, bool key) {  // Test OK
  int l = msg.size();
  int ll = (l - 1) << 2;
  if (key) {
  int m = msg[l - 1];
  if (m < ll - 3 || m > ll)
    return "";
  ll = m;
  }
  string result;
  for (int i = 0; i < l; i++)
    result.push_back(static_cast<char>(msg[i] & 0xFF) +
              static_cast<char>(msg[i] >> 8 & 0xFF) +
              static_cast<char>(msg[i] >> 16 & 0xFF) +
              static_cast<char>(msg[i] >> 24 & 0xFF));
  if (key)
    return result.substr(0, ll);
  return result;
}

const string get_xencode(string const &msg, string const &key) {
  if (msg.empty())
    return "";
  auto pwd = sencode(msg, true);
  auto pwdk = sencode(key, false);
  if (pwdk.size() < 4) {
    auto len_pwdk = pwdk.size();
    for (int i = 0; i < 4 - len_pwdk; i++)
      pwdk.push_back(0);
  }
  auto n = pwd.size() - 1;
  auto z = pwd[n];
  auto y = pwd[0];
  auto c = 0x86014019 | 0x183639A0;
  auto m = 0;
  auto e = 0;
  auto p = 0;
  auto q = 6 + 52 / (n + 1);
  auto d = 0;
  while (q > 0) {
    d += c & (0x8CE0D9BF | 0x731F2640);
    e = d >> 2 & 3;
    p = 0;
    while (p < n) {
      y = pwd[p + 1];
      m = z >> 5 ^ y << 2;
      m += (y >> 3 ^ z << 4) ^ (d ^ y);
      m += pwdk[(p & 3) ^ e] ^ z;
      pwd[p] += m & (0xEFB8D130 | 0x10472ECF);
      z = pwd[p];
      p += 1;
    }
    y = pwd[0];
    m = z >> 5 ^ y << 2;
    m += (y >> 3 ^ z << 4) ^ (d ^ y);
    m += pwdk[(p & 3) ^ e] ^ z;
    pwd[n] += m & (0xBB390742 | 0x44C6F8BD);
    z = pwd[n];
    q -= 1;
  }
  return lencode(pwd, false);
}

const string &get_md5(string const &password, string const &token) {
  static string result = hmac<MD5>(password, token);
  return result;
}

const string &get_sha1(string const &value) {
  SHA1 sha1;
  static string result = sha1(value);
  return result;
}

const string &get_base64(string const &value) {
  static string result = base64_encode(value);
  return result;
}

cpr::Header header = {
    {"User-Agent", "Mozilla/5.0 (Windows NT 10.0 WOW64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/63.0.3239.26 Safari/537.36"}};

string const init_url = "http://10.1.1.131";
string const get_challenge_api = "http://10.1.1.131/cgi-bin/get_challenge";
string const srun_portal_api = "http://10.1.1.131/cgi-bin/srun_portal";
string const rad_userinfo_api = "http://10.1.1.131/cgi-bin/rad_user_info";
string const n = "200";
string const type = "1";
string const ac_id = "1";
string const enc = "srun_bx1";
string token = "Unknown";
string username = "Unknown";
string password = "Unknown";
string i;
string ip = "Unknown";
string hmd5 = "Unknown";
string chksum = "Unknown";

void init_getip() {
  auto init_res = cpr::Get(cpr::Url{init_url.c_str()}, header);
  regex e("\\d{0,3}\\.\\d{0,3}\\.\\d{0,3}\\.\\d{0,3}");
  smatch sm;
  string target = init_res.text;
#ifdef __DEBUG
  cout << "initaling ip address..." << endl;
#endif
  if (regex_search(target, sm, e))
    ip = sm[0];
#ifdef __DEBUG
  cout << "ip: " << ip << endl;
#endif
}

// get current local time stamp
int64_t getCurrentLocalTimeStamp() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

void get_token() {
#ifdef __DEBUG
  cout << "getting token..." << endl;
#endif
  cpr::Parameters get_challenge_params =
      cpr::Parameters{{"callback", "jQuery112404953340710317169_" +
                                       to_string(getCurrentLocalTimeStamp())},
                      {"username", username},
                      {"ip", ip},
                      {"_", to_string(getCurrentLocalTimeStamp())}};
  auto get_challenge_res = cpr::Get(cpr::Url{get_challenge_api.c_str()},
                                    get_challenge_params, header);
  regex e("\"challenge\":\"(.*?)\"");
  smatch sm;
  string target = get_challenge_res.text;
  if (regex_search(target, sm, e))
    token = sm[1];
#ifdef __DEBUG
  cout << "====token info====\n" << target << endl;
  cout << "token is: " << token << endl;
#endif
}

const string get_chksum() {
  auto chkstr = token + username;
  chkstr += token + hmd5;
  chkstr += token + ac_id;
  chkstr += token + ip;
  chkstr += token + n;
  chkstr += token + type;
  chkstr += token + i;
  return chkstr;
}

string const get_info() {   // Test OK
  string info_temp = "{\"username\":" + username + ",\"password\":" + password +
                     ",\"ip\":" + ip + ",\"acid\":" + ac_id +
                     ",\"enc_ver\":" + enc + "}";
  replace(info_temp.begin(), info_temp.end(), '\'', '\"');
  info_temp.erase(remove_if(info_temp.begin(), info_temp.end(), ::isspace),
                  info_temp.end());
  return info_temp;
}

void encode() {
  i = get_info();
  i = "{SRBX1}" + get_base64(get_xencode(i, token));
  hmd5 = get_md5(password, token);
  chksum = get_sha1(get_chksum());
#ifdef __DEBUG
  cout << "====encode work====" << endl;
  cout << "i = " << i << endl;
  cout << "hmd5 = " << hmd5 << endl;
  cout << "chksum = " << chksum << endl;
  cout << "All encode work done." << endl;
#endif
}

void init_work() {
  init_getip();
  get_token();
  encode();
}

void login() {
  auto srun_portal_params =
      cpr::Parameters{{"callback", "jQuery11240645308969735664_" +
                                       to_string(getCurrentLocalTimeStamp())},
                      {"action", "login"},
                      {"username", username},
                      {"password", "{MD5}" + hmd5},
                      {"ac_id", ac_id},
                      {"ip", ip},
                      {"chksum", chksum},
                      {"info", i},
                      {"n", n},
                      {"type", type},
                      {"os", "windows+10"},
                      {"name", "windows"},
                      {"double_stack", "0"},
                      {"_", to_string(getCurrentLocalTimeStamp())}};
  auto srun_portal_res =
      cpr::Get(cpr::Url{srun_portal_api}, srun_portal_params, header);
#ifdef __DEBUG
  cout << srun_portal_params.content << endl;
  cout << srun_portal_res.text << endl;
#endif
  regex e("E[0-9]{4}");
  smatch sm;
  string target = srun_portal_res.text;
  regex_search(target, sm, e);
  auto code = sm[0].str();
  if (code == "E0000")
    cout << "Login success." << endl;
  else
    cout << "Login failed. Error Code: " << code << endl;
}

int main(int argc, const char **argv) {
  username = "2108570020058";
  password = "snipexl1997";

  init_work();
  return 0;
}