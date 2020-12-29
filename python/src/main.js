$(function () {
    // portal 初始化
    var portal = new Portal(CONFIG);

    // 若配置开启通知，则查询通知内容，并根据配置生成通知
    if (CREATER.notice) portal.getNotice({
        alert: CREATER.noticeAlert,
        index: CREATER.noticeIndex,
        time: CREATER.noticeTime
    });

    // 查询用户在线信息
    portal.info({
        params: {
            // 查询用户在线信息请求携带的参数
            // user_name: portal.getCookie('username') || ''
        },
        online: function (res) {
            // Portal 类为 ajax 请求携带请求头的方法
            // portal.setRequestHead({ 'User-Auth' : portal.userInfo.username });
        },
        offline: function (res) {
        }
    });

    // 若存在且开启记住密码功能
    if ($('#remember').length && CREATER.remember) {
        // 从 Cookie 中取出记住的账号与密码
        var info = portal.getCookie('remember');
        // 若 Cookie 中存在记住的账号与密码
        if (info) {
            // 克隆自 $.base64，防止污染
            var base64 = portal.clone($.base64);
            // base64 设置 Alpha
            base64.setAlpha('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/');
            info = JSON.parse(base64.decode(info));
            $('#username').val(info.username);
            $('#password').val(info.password);
            $('#remember').prop('checked', true);
        }
    }

    // 若存在且开启忘记密码功能，且修改密码方式为 Portal 修改
    if ($('#forget').length && CREATER.forgetMethod === 'portal') portal.useForget();
    // 若存在且开启充值缴费功能，且页面上有充值缴费按钮
    if ($('.btn-pay').length && CREATER.usePay) portal.usePay();

    // 点击登录按钮 - 账号认证
    $('#login-account').click(function () {
        var username = $('#username').val().replace(/ /g, '');
        var password = $('#password').val();
        // 若页面不存在 domain，则 domain 为空
        var domain = $('#domain').val();
        // 若存在 domain 且 domain 存在排序情况，则对 domain 进行处理
        // 该处理方式是为了防止 app.conf 中 domain 排序不规范写成 1 - @domain 的情况
        if (domain && domain.substring(0, 1) !== '@') domain = '@' + domain.split('@')[1];
        // 对账号进行非空校验
        if (!portal.fieldCheck(username, 'blank')) return $('#username').focus();
        // 对密码进行非空校验
        if (!portal.fieldCheck(password, 'blank')) return $('#password').focus();
        // 写入用户信息
        portal.userInfo.username = username;
        portal.userInfo.password = password;
        portal.userInfo.domain = domain || '';

        // Portal 认证方法
        portal.login({
            // 认证方式为账号认证
            type: 'account',
            // 认证成功
            success: function () {
                // 若勾选记住密码
                if ($('#remember').prop('checked')) portal.remember(true);
                // 若未勾选记住密码 或 不存在记住密码功能
                if (!$('#remember').prop('checked')) portal.remember(false);
                // 重定向至成功页
                portal.toSuccess();
            }
        });
    });

    // 点击登录按钮 - 邀请码认证
    $('#login-token').click(function () {
        var password = $('#password').val();
        // 对密码进行非空校验
        if (!portal.fieldCheck(password, 'blank')) return $('#password').focus();
        // 写入用户信息
        portal.userInfo.username = CREATER.tokenUser;
        portal.userInfo.password = password;
        portal.userInfo.domain = '';
        // Portal 认证
        portal.login({
            // 认证方式为账号认证
            type: 'account'
        });
    });

    // 点击登录按钮 - 短信认证
    $('#login-sms').click(function () {
        var phone = $('#phone').val().replace(/ /g, '');
        var vcode = $('#vcode').val();
        // 对手机号进行非空校验 (存在给账号发送验证码情况，故不校验手机号格式)
        if (!portal.fieldCheck(phone, 'blank')) return $('#phone').focus();
        // 对验证码进行非空校验
        if (!portal.fieldCheck(vcode, 'blank')) return $('#vcode').focus();
        // 写入用户信息
        portal.userInfo.phone = phone;
        portal.userInfo.vcode = vcode;
        // Portal 认证
        portal.login({
            // 认证方式为短信认证
            type: 'sms'
        });
    });

    // 点击登录按钮 - OTP 认证
    $('#login-otp').click(function () {
        var username = $('#username').val().replace(/ /g, '');
        var password = $('#password').val();
        // 对账号进行非空校验
        if (!portal.fieldCheck(username, 'blank')) return $('#username').focus();
        // 对密码进行非空校验
        if (!portal.fieldCheck(password, 'blank')) return $('#password').focus();
        // 写入用户信息
        portal.userInfo.username = username;
        portal.userInfo.password = password;

        // Portal 认证方法
        portal.login({
            // 认证方式为账号认证
            type: 'otp',
        });
    });

    // 点击登录按钮 - Cisco 认证
    $('#login-cisco').click(function () {
        var username = $('#username').val().replace(/ /g, '');
        var password = $('#password').val();
        // 对账号进行非空校验
        if (!portal.fieldCheck(username, 'blank')) return $('#username').focus();
        // 对密码进行非空校验
        if (!portal.fieldCheck(password, 'blank')) return $('#password').focus();
        // 写入用户信息
        portal.userInfo.username = username;
        portal.userInfo.password = password;
        // Portal 认证方法
        portal.login({
            // 认证方式为 Cisco 认证
            type: 'cisco',
        });
    })

    // 点击登录按钮 - Cisco SMS 认证
    $('#login-cisco-sms').click(function () {
        var phone = $('#phone').val().replace(/ /g, '');
        var vcode = $('#vcode').val();
        // 对手机号进行非空校验 (存在给账号发送验证码情况，故不校验手机号格式)
        if (!portal.fieldCheck(phone, 'blank')) return $('#phone').focus();
        // 对验证码进行非空校验
        if (!portal.fieldCheck(vcode, 'blank')) return $('#vcode').focus();
        // 写入用户信息
        portal.userInfo.phone = phone;
        portal.userInfo.vcode = vcode;
        // 写入隐藏 input
        $('input[name="username"]').val(phone);
        $('input[name="password"]').val(vcode);
        // Portal 认证方法
        portal.login({
            // 认证方式为 Cisco 认证
            type: 'cisco',
        });
    })

    // 点击注销按钮
    $('#logout').click(function () {
        portal.confirm({
            message: portal.translate('LogoutConfirm'),
            confirm: function () {
                // Portal 注销
                portal.logout();
            },
            cancel: function () { }
        });
    });

    // 点击自助服务按钮
    $('#self-service').click(function () {
        // 若在登录页面点击，则读取账号及密码，进行自助服务单点登录
        if (!portal.online) {
            portal.userInfo.username = $('#username').val();
            portal.userInfo.password = $('#password').val();
        }
        // 开启自助服务
        portal.toSelfService();
    });

    // 回车触发认证
    $('input').keydown(function (e) {
        // 只有在输入框处于 focus 状态，且按下的按键是回车时才触发回车认证
        if (!$(this).is(':focus') || e.keyCode !== 13) return;
        $(this).blur();
        $('#login-account').click();
        $('#login-token').click();
        $('#login-sms').click();
    });

    // 点击 Logo
    $('.logo').click(function (e) {
        if (CREATER.logoLink) window.open(CREATER.logoLink);
    });

    // 点击忘记密码
    $('#forget').click(function (e) {
        // 修改密码模式为 portal 则开启修改密码对话框
        if (CREATER.forgetMethod === 'portal') portal.dialog.open('changePassword');
        // 修改密码模式为自助服务则开启自助服务修改密码页面
        if (CREATER.forgetMethod === 'selfService') portal.toSelfService('/forget');
        // 修改密码模式为外部链接，但未配置链接地址，则开启自助服务修改密码页面
        if (CREATER.forgetMethod === 'link' && !CREATER.forgetUrl) portal.toSelfService('/forget');
        // 修改密码模式为外部链接，配置有链接地址，则开启链接地址
        if (CREATER.forgetMethod === 'link' && CREATER.forgetUrl) window.open(CREATER.forgetUrl);
    });

    // 获取验证码
    $('#btn-get-vcode').click(function () {
        if ($(this).attr('data-status') === 'disable') return;
        // 去除手机号中空格
        var phone = $('#phone').val().replace(/ /g, '');
        // 存在给账号发送验证码情况，故不校验手机号格式
        if (!portal.fieldCheck(phone, 'blank')) return $('#phone').focus();
        // 发送验证码
        portal.sendVCode({
            phone: phone,
            success: function () {
                portal.confirm(portal.translate('SendVerifyCodeOK'));
                countdown(60);
            }
        });
        function countdown(number) {
            var btn = $('#btn-get-vcode');
            var timer = setInterval(function () {
                btn.attr('data-status', 'disable').html(number + portal.translate('SendAgain'));
                number -= 1;
                if (number === 0) {
                    btn.attr('data-status', '').html(portal.translate('GetVerifyCode'));
                    clearInterval(timer);
                }
            }, 1000);
        }
    });

    // 切换认证方式
    $('.panel-row-item.login-mode').click(function () {
        var mode = $(this).attr('data-mode');
        if (mode === 'wechat') return portal.login({ type: 'wechat' });
        if (mode === 'account' && !Portal.mobile) return Portal.redirect('/srun_portal_pc');
        if (mode === 'sms' && !Portal.mobile) return Portal.redirect('/srun_portal_sms');
        if (mode === 'otp' && !Portal.mobile) return Portal.redirect('/srun_portal_otp');
        if (mode === 'sso') return Portal.redirect('/srun_portal_sso');
        if (mode === 'qrcode') return Portal.redirect('/srun_portal_scan_qrcode');
        if (mode === 'wework') return Portal.redirect('/srun_portal_wework');
        if (mode === 'token') return Portal.redirect('/srun_portal_token');
        // Mobile
        if (mode === 'account' && Portal.mobile) return Portal.redirect('/srun_portal_phone');
        if (mode === 'sms' && Portal.mobile) return Portal.redirect('/srun_portal_sms_mobile');
        if (mode === 'otp' && Portal.mobile) return Portal.redirect('/srun_portal_otp_mobile');

        if (mode === 'cisco') return Portal.redirect('/srun_portal_cisco');
        if (mode === 'cisco-sms') return Portal.redirect('/srun_portal_cisco_sms');
    })

    // 切换语言
    $('#change-lang').change(function () {
        portal.changeLang($(this).val());
    });

    // 点击使用协议
    $("#protocol-content").click(function () {
        // 弹框显示协议内容
        portal.confirm({
            title: portal.portalInfo.protocol.title,
            message: portal.portalInfo.protocol.content,
            confirm: function () {
                if (!$('#protocol').prop('checked')) $('#protocol').prop('checked', true);
            }
        });
    });

    if (navigator.userAgent.includes('MSIE 9.0')) {
        $('.iconfont, .material-icons').hide();
        $("#app .section .panel-login .input-box").css("padding-left", "20px");
    }
});
