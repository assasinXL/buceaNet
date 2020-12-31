#include <cpr/cpr.h>
#include <string>
#include <vector>
#include <map>
#include <regex>
#include <iostream>
#include <ctime>

#include "hmac.h"
#include "md5.h"
#include "sha1.h"


using namespace std;

#undef _ALPHA
#define __DEBUG

const char _PADCHAR = '=';
const char *_ALPHA =
    "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";

string force(string const &msg) {
  string ret;
  for (auto w : ret)
    ret.push_back(static_cast<uint8_t>(w));
  return ret;
}

uint8_t ordat(string const &msg, size_t idx) {
  return (msg.size() > idx) ? static_cast<uint8_t>(msg[idx]) : 0;
}

string sencode(string const &msg, bool key) {
  size_t l = msg.size();
  string pwd;
  for (auto i = 0; i < l; i += 4)
    pwd.push_back(ordat(msg, i) | ordat(msg, i + 1) << 8 |
                  ordat(msg, i + 2) << 16 | ordat(msg, i + 3) << 24);
  if (key)
    pwd.push_back(static_cast<uint8_t>(l));
  return pwd;
}

string lencode(string &msg, bool key) {
  size_t l = msg.size();
  size_t ll = (l - 1) << 2;
  if (key) {
    uint8_t m = msg[l - 1];
    if (m < ll - 3 || m > ll)
      return "";
    ll = static_cast<size_t>(m);
  }
  for (auto i = 0; i < l; i++)
    msg[i] = (static_cast<uint8_t>(msg[i] & 0xFF) +
              static_cast<uint8_t>((msg[i] >> 8) & 0xFF) +
              static_cast<uint8_t>((msg[i] >> 16) & 0xFF) +
              static_cast<uint8_t>((msg[i] >> 24) & 0xFF));
  string res;
  if (key)
    msg.assign(res.begin(), res.begin() + ll);
  else
    msg.assign(res.begin(), res.end());
  return res;
}

uint8_t _getbyte(string const &s, size_t i) {
  uint8_t x = static_cast<uint8_t>(s[i]);
  if (x > 255)
    throw "INVALID_CHARACTER_ERR: DOM Exception 5";
  return 0;
}

string get_xencode(string const &msg, string const &key) {
  if (msg.empty())
    return "";
  auto pwd = sencode(msg, true);
  auto pwdk = sencode(key, false);
  if (pwdk.size() < 4)
    for (auto i = 0; i < 4 - pwdk.size(); i++)
      pwdk += '0';
  auto n = pwd.size() - 1;
  auto z = pwd[n];
  auto y = pwd[0];
  auto c = 0x86014019 | 0x183639A0;
  auto m = 0;
  auto e = 0;
  auto p = 0;
  auto q = floor(6 + 52 / (n + 1));
  auto d = 0;
  while (0 < q) {
    d = d + c & (0x8CE0D9BF | 0x731F2640);
    e = d >> 2 & 3;
    p = 0;
    while (p < n) {
      y = pwd[p + 1];
      m = z >> 5 ^ y << 2;
      m = m + ((y >> 3 ^ z << 4) ^ (d ^ y));
      m = m + (pwdk[(p & 3) ^ e] ^ z);
      pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF);
      z = pwd[p];
      p += 1;
    }
    y = pwd[0];
    m = z >> 5 ^ y << 2;
    m = m + ((y >> 3 ^ z << 4) ^ (d ^ y));
    m = m + (pwdk[(p & 3) ^ e] ^ z);
    pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD);
    z = pwd[n];
    q -= 1;
  }
  return lencode(pwd, false);
}

string get_base64(string const &s) {
  auto i = 0;
  auto b10 = 0;
  vector<uint8_t> x;
  auto imax = s.size() - s.size() % 3;
  if (s.empty())
    return s;
  for (auto i = 0; i < imax; i += 3) {
    b10 = ((_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8) |
           _getbyte(s, i + 2));
    x.push_back(_ALPHA[(b10 >> 18)]);
    x.push_back(_ALPHA[((b10 >> 12) & 63)]);
    x.push_back(_ALPHA[((b10 >> 6) & 63)]);
    x.push_back(_ALPHA[(b10 & 63)]);
  }
  i = imax;
  if (s.size() - imax == 1) {
    b10 = _getbyte(s, i) << 16;
    x.push_back(_ALPHA[(b10 >> 18)] + _ALPHA[((b10 >> 12) & 63)] + _PADCHAR +
                _PADCHAR);
  } else if (s.size() - imax == 2) {
    b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8);
    x.push_back(_ALPHA[(b10 >> 18)] + _ALPHA[((b10 >> 12) & 63)] +
                _ALPHA[((b10 >> 6) & 63)] + _PADCHAR);
  }
  string res;
  x.assign(res.begin(), res.end());
  return res;
}

string get_md5(string const &password, string const &token) {
  return hmac<MD5>(password, token);
}

string get_sha1(string const &value) {
  SHA1 sha1;
  return sha1(value);
}

cpr::Header header = {
  {"User-Agent", "Mozilla/5.0 (Windows NT 10.0 WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.26 Safari/537.36"}
};

string const init_url = "http://10.1.1.131";
string const get_challenge_api = "http://10.1.1.131/cgi-bin/get_challenge";
string const srun_portal_api = "http://10.1.1.131/cgi-bin/srun_portal";
string const rad_userinfo_api = "http://10.1.1.131/cgi-bin/rad_user_info";
string const n = "200";
string const type = "1";
string const ac_id = "1";
string const enc = "srun_bx1";
string token;
string username;
string password;
string i;
string ip;
string hmd5;
string chksum;

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

string const get_info() {
  string info_temp = "{\"username\":" + username +
                     ",\"password\":" + password + ",\"ip\":" + ip +
                     ",\"acid\":" + ac_id + ",\"enc_ver\":" + enc + "}";
  i = info_temp;
  return i;
}

void init_getip() {
  auto init_res = cpr::Get(cpr::Url{init_url.c_str()}, header);
  regex e("ip(\\s*):(\\s*)\"(.*) \"");
  smatch sm;
  string target = init_res.text;
#ifdef __DEBUG
  cout << "initaling ip address..." << endl;
#endif
  regex_search(target, sm, e);
  ip = sm[3];
#ifdef __DEBUG
  cout << "ip: " << ip << endl;
#endif
}

// get current local time stamp
int64_t getCurrentLocalTimeStamp() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

void get_token() {
#ifdef __DEBUG
  cout << "getting token..." << endl;
#endif
  cpr::Parameters get_challenge_params = cpr::Parameters{
    {"callback", "jQuery112404953340710317169_" + to_string(getCurrentLocalTimeStamp())},
    {"username", username},
    {"ip", ip},
    {"_", to_string(getCurrentLocalTimeStamp())}};
  auto get_challenge_res = cpr::Get(cpr::Url{get_challenge_api.c_str()},
                                    get_challenge_params, header);
  regex e("\"challenge\":\"(.*?)\"");
  smatch sm;
  string target = get_challenge_res.text;
  regex_search(target, sm, e);
#ifdef __DEBUG
  cout << target << endl;
  cout << "token is: " << token << endl;
#endif
}

void encode() {
  i = get_info();
    i = "{SRBX1}" + get_base64(get_xencode(i, token));
    hmd5 = get_md5(password, token);
    chksum = get_sha1(get_chksum());
#ifdef __DEBUG
    cout << "All encode work done." << endl;
#endif
}

void init_work() {
  init_getip();
  get_token();
  encode();
}

void login() {
  auto srun_portal_params = cpr::Parameters{
    {"callback", "jQuery11240645308969735664_" + to_string(getCurrentLocalTimeStamp())},
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
    {"_", to_string(getCurrentLocalTimeStamp())}
  };
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
  login();
  return 0;
}