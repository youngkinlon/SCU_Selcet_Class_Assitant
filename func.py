# -*- coding: UTF-8 -*-
import ast
import json
import random
import re
import time
from PIL import Image

from config import *

def hex_md5(string, ver=None):
    def md5_rotate_left(lvalue, ishift_bits):
        return (lvalue << ishift_bits) | (lvalue >> (32 - ishift_bits)) & 0xFFFFFFFF

    def md5_add_unsigned(lx, ly):
        lx8 = lx & 0x80000000
        ly8 = ly & 0x80000000
        lx4 = lx & 0x40000000
        ly4 = ly & 0x40000000
        lresult = (lx & 0x3FFFFFFF) + (ly & 0x3FFFFFFF)
        if lx4 & ly4:
            return (lresult ^ 0x80000000 ^ lx8 ^ ly8) & 0xFFFFFFFF
        if lx4 | ly4:
            if lresult & 0x40000000:
                return (lresult ^ 0xC0000000 ^ lx8 ^ ly8) & 0xFFFFFFFF
            else:
                return (lresult ^ 0x40000000 ^ lx8 ^ ly8) & 0xFFFFFFFF
        else:
            return (lresult ^ lx8 ^ ly8) & 0xFFFFFFFF

    def md5_f(x, y, z):
        return (x & y) | ((~x) & z) & 0xFFFFFFFF

    def md5_g(x, y, z):
        return (x & z) | (y & (~z)) & 0xFFFFFFFF

    def md5_h(x, y, z):
        return (x ^ y ^ z) & 0xFFFFFFFF

    def md5_i(x, y, z):
        return (y ^ (x | (~z))) & 0xFFFFFFFF

    def md5_ff(a, b, c, d, x, s, ac):
        a = md5_add_unsigned(a, md5_add_unsigned(md5_add_unsigned(md5_f(b, c, d), x), ac))
        return md5_add_unsigned(md5_rotate_left(a, s), b)

    def md5_gg(a, b, c, d, x, s, ac):
        a = md5_add_unsigned(a, md5_add_unsigned(md5_add_unsigned(md5_g(b, c, d), x), ac))
        return md5_add_unsigned(md5_rotate_left(a, s), b)

    def md5_hh(a, b, c, d, x, s, ac):
        a = md5_add_unsigned(a, md5_add_unsigned(md5_add_unsigned(md5_h(b, c, d), x), ac))
        return md5_add_unsigned(md5_rotate_left(a, s), b)

    def md5_ii(a, b, c, d, x, s, ac):
        a = md5_add_unsigned(a, md5_add_unsigned(md5_add_unsigned(md5_i(b, c, d), x), ac))
        return md5_add_unsigned(md5_rotate_left(a, s), b)

    def md5_convert_to_word_array(string):
        lmessage_length = len(string)
        lnumber_of_words_temp1 = lmessage_length + 8
        lnumber_of_words_temp2 = (lnumber_of_words_temp1 - (lnumber_of_words_temp1 % 64)) // 64
        lnumber_of_words = (lnumber_of_words_temp2 + 1) * 16
        lword_array = [0] * lnumber_of_words
        lbyte_position = 0
        lbyte_count = 0
        while lbyte_count < lmessage_length:
            lword_count = (lbyte_count - (lbyte_count % 4)) // 4
            lbyte_position = (lbyte_count % 4) * 8
            lword_array[lword_count] = lword_array[lword_count] | (string[lbyte_count] << lbyte_position)
            lbyte_count += 1
        lword_count = (lbyte_count - (lbyte_count % 4)) // 4
        lbyte_position = (lbyte_count % 4) * 8
        lword_array[lword_count] = lword_array[lword_count] | (0x80 << lbyte_position)
        lword_array[lnumber_of_words - 2] = lmessage_length << 3
        lword_array[lnumber_of_words - 1] = lmessage_length >> 29
        return lword_array

    def md5_word_to_hex(lvalue):
        word_to_hex_value = ""
        for lcount in range(4):
            lbyte = (lvalue >> (lcount * 8)) & 255
            word_to_hex_value_temp = "0" + hex(lbyte)[2:]
            word_to_hex_value += word_to_hex_value_temp[-2:]
        return word_to_hex_value

    def md5_utf8_encode(string):
        utftext = bytearray()
        for n in range(len(string)):
            c = ord(string[n])
            if c < 128:
                utftext.append(c)
            elif 127 < c < 2048:
                utftext.append((c >> 6) | 192)
                utftext.append((c & 63) | 128)
            else:
                utftext.append((c >> 12) | 224)
                utftext.append(((c >> 6) & 63) | 128)
                utftext.append((c & 63) | 128)
        return utftext

    s11 = 7; s12 = 12; s13 = 17; s14 = 22
    s21 = 5; s22 = 9; s23 = 14; s24 = 20
    s31 = 4; s32 = 11; s33 = 16; s34 = 23
    s41 = 6; s42 = 10; s43 = 15; s44 = 21

    salt = b"" if ver == "1.8" else b"{Urp602019}"
    utftext = md5_utf8_encode(string) + salt

    x = md5_convert_to_word_array(utftext)
    a = 0x67452301 & 0xFFFFFFFF
    b = 0xEFCDAB89 & 0xFFFFFFFF
    c = 0x98BADCFE & 0xFFFFFFFF
    d = 0x10325476 & 0xFFFFFFFF

    for k in range(0, len(x), 16):
        aa = a
        bb = b
        cc = c
        dd = d
        a = md5_ff(a, b, c, d, x[k + 0], s11, 0xD76AA478)
        d = md5_ff(d, a, b, c, x[k + 1], s12, 0xE8C7B756)
        c = md5_ff(c, d, a, b, x[k + 2], s13, 0x242070DB)
        b = md5_ff(b, c, d, a, x[k + 3], s14, 0xC1BDCEEE)
        a = md5_ff(a, b, c, d, x[k + 4], s11, 0xF57C0FAF)
        d = md5_ff(d, a, b, c, x[k + 5], s12, 0x4787C62A)
        c = md5_ff(c, d, a, b, x[k + 6], s13, 0xA8304613)
        b = md5_ff(b, c, d, a, x[k + 7], s14, 0xFD469501)
        a = md5_ff(a, b, c, d, x[k + 8], s11, 0x698098D8)
        d = md5_ff(d, a, b, c, x[k + 9], s12, 0x8B44F7AF)
        c = md5_ff(c, d, a, b, x[k + 10], s13, 0xFFFF5BB1)
        b = md5_ff(b, c, d, a, x[k + 11], s14, 0x895CD7BE)
        a = md5_ff(a, b, c, d, x[k + 12], s11, 0x6B901122)
        d = md5_ff(d, a, b, c, x[k + 13], s12, 0xFD987193)
        c = md5_ff(c, d, a, b, x[k + 14], s13, 0xA679438E)
        b = md5_ff(b, c, d, a, x[k + 15], s14, 0x49B40821)
        a = md5_gg(a, b, c, d, x[k + 1], s21, 0xF61E2562)
        d = md5_gg(d, a, b, c, x[k + 6], s22, 0xC040B340)
        c = md5_gg(c, d, a, b, x[k + 11], s23, 0x265E5A51)
        b = md5_gg(b, c, d, a, x[k + 0], s24, 0xE9B6C7AA)
        a = md5_gg(a, b, c, d, x[k + 5], s21, 0xD62F105D)
        d = md5_gg(d, a, b, c, x[k + 10], s22, 0x2441453)
        c = md5_gg(c, d, a, b, x[k + 15], s23, 0xD8A1E681)
        b = md5_gg(b, c, d, a, x[k + 4], s24, 0xE7D3FBC8)
        a = md5_gg(a, b, c, d, x[k + 9], s21, 0x21E1CDE6)
        d = md5_gg(d, a, b, c, x[k + 14], s22, 0xC33707D6)
        c = md5_gg(c, d, a, b, x[k + 3], s23, 0xF4D50D87)
        b = md5_gg(b, c, d, a, x[k + 8], s24, 0x455A14ED)
        a = md5_gg(a, b, c, d, x[k + 13], s21, 0xA9E3E905)
        d = md5_gg(d, a, b, c, x[k + 2], s22, 0xFCEFA3F8)
        c = md5_gg(c, d, a, b, x[k + 7], s23, 0x676F02D9)
        b = md5_gg(b, c, d, a, x[k + 12], s24, 0x8D2A4C8A)
        a = md5_hh(a, b, c, d, x[k + 5], s31, 0xFFFA3942)
        d = md5_hh(d, a, b, c, x[k + 8], s32, 0x8771F681)
        c = md5_hh(c, d, a, b, x[k + 11], s33, 0x6D9D6122)
        b = md5_hh(b, c, d, a, x[k + 14], s34, 0xFDE5380C)
        a = md5_hh(a, b, c, d, x[k + 1], s31, 0xA4BEEA44)
        d = md5_hh(d, a, b, c, x[k + 4], s32, 0x4BDECFA9)
        c = md5_hh(c, d, a, b, x[k + 7], s33, 0xF6BB4B60)
        b = md5_hh(b, c, d, a, x[k + 10], s34, 0xBEBFBC70)
        a = md5_hh(a, b, c, d, x[k + 13], s31, 0x289B7EC6)
        d = md5_hh(d, a, b, c, x[k + 0], s32, 0xEAA127FA)
        c = md5_hh(c, d, a, b, x[k + 3], s33, 0xD4EF3085)
        b = md5_hh(b, c, d, a, x[k + 6], s34, 0x4881D05)
        a = md5_hh(a, b, c, d, x[k + 9], s31, 0xD9D4D039)
        d = md5_hh(d, a, b, c, x[k + 12], s32, 0xE6DB99E5)
        c = md5_hh(c, d, a, b, x[k + 15], s33, 0x1FA27CF8)
        b = md5_hh(b, c, d, a, x[k + 2], s34, 0xC4AC5665)
        a = md5_ii(a, b, c, d, x[k + 0], s41, 0xF4292244)
        d = md5_ii(d, a, b, c, x[k + 7], s42, 0x432AFF97)
        c = md5_ii(c, d, a, b, x[k + 14], s43, 0xAB9423A7)
        b = md5_ii(b, c, d, a, x[k + 5], s44, 0xFC93A039)
        a = md5_ii(a, b, c, d, x[k + 12], s41, 0x655B59C3)
        d = md5_ii(d, a, b, c, x[k + 3], s42, 0x8F0CCC92)
        c = md5_ii(c, d, a, b, x[k + 10], s43, 0xFFEFF47D)
        b = md5_ii(b, c, d, a, x[k + 1], s44, 0x85845DD1)
        a = md5_ii(a, b, c, d, x[k + 8], s41, 0x6FA87E4F)
        d = md5_ii(d, a, b, c, x[k + 15], s42, 0xFE2CE6E0)
        c = md5_ii(c, d, a, b, x[k + 6], s43, 0xA3014314)
        b = md5_ii(b, c, d, a, x[k + 13], s44, 0x4E0811A1)
        a = md5_ii(a, b, c, d, x[k + 4], s41, 0xF7537E82)
        d = md5_ii(d, a, b, c, x[k + 11], s42, 0xBD3AF235)
        c = md5_ii(c, d, a, b, x[k + 2], s43, 0x2AD7D2BB)
        b = md5_ii(b, c, d, a, x[k + 9], s44, 0xEB86D391)
        a = md5_add_unsigned(a, aa)
        b = md5_add_unsigned(b, bb)
        c = md5_add_unsigned(c, cc)
        d = md5_add_unsigned(d, dd)

    return (md5_word_to_hex(a) + md5_word_to_hex(b) + md5_word_to_hex(c) + md5_word_to_hex(d)).lower()

def getToken(session):
    res = session.get(url=token_url, headers=header).content
    print(res)
    matchObj = re.findall(
        r'<input type="hidden" id="tokenValue" name="tokenValue" value="(.*)">', res.decode())
    if matchObj:
        return matchObj[0]
    else:
        print("Token获取失败")
        exit()


def downloadCaptcha(session):
    with open("captcha.jpg", "wb") as f:
        f.write(session.get(url=captcha_url, headers=header).content)

# 初始化OCR（仅识别，不检测文字框；适合验证码）

def login(session):
    token = getToken(session)
    print("your token is", token)
    print("登录")
    cpaptcha_switch = input("是否尝试自动识别验证码?[y/n]")

    if cpaptcha_switch == 'y' or cpaptcha_switch == 'Y':
        import  muggle_ocr
        while True:
            with open("captcha.jpg", 'rb') as f:
                captcha_bytes = f.read()
                sdk = muggle_ocr.SDK(model_type=muggle_ocr.ModelType.Captcha)
                text = sdk.predict(image_bytes=captcha_bytes)
                pwd = j_password
                inner1 = hex_md5(pwd)  # MD5(pwd)
                part1 = hex_md5(inner1, "1.8")  # MD5(MD5(pwd) + "1.8")
                inner2 = hex_md5(pwd, "1.8")  # MD5(pwd + "1.8")
                part2 = hex_md5(inner2, "1.8")  # MD5(MD5(pwd+"1.8") + "1.8")
                encrypted_pwd = part1 + '*' + part2
                login_data = {
                    'tokenValue': token,
                    'j_username': j_username,
                    'j_password': encrypted_pwd,
                    'j_captcha': text
                }
                print("识别的验证码为:{}".format(text))
                try:
                    response = session.post(
                        url=login_url, headers=header, data=login_data).text
                    if "欢迎您" in response:
                        print("登陆成功！")
                        return "success"
                    else:
                        print("自动识别验证码失败，三秒后准备尝试重新登录!")
                        time.sleep(3)
                        return "failed"
                except Exception as e:
                    print("def login() 出现问题:" + str(e))
                    return None
    else:
        print("手动")
        img = Image.open('captcha.jpg')
        img.show()
        pwd = j_password
        inner1 = hex_md5(pwd)  # MD5(pwd)
        part1 = hex_md5(inner1, "1.8")  # MD5(MD5(pwd) + "1.8")
        inner2 = hex_md5(pwd, "1.8")  # MD5(pwd + "1.8")
        part2 = hex_md5(inner2, "1.8")  # MD5(MD5(pwd+"1.8") + "1.8")
        encrypted_pwd = part1 + '*' + part2
        login_data = {
            'tokenValue': token,
            'j_username': j_username,
            'j_password': encrypted_pwd,
            'j_captcha': input("请输入验证码:")
        }
        try:
            response = session.post(
                url=login_url, headers=header, data=login_data).text
            print(response)
            print(f"▶ HTTP状态码: {response.status_code}")
            if "欢迎您" in response:
                print("登陆成功！")
                return "success"
            else:
                return "failed"
        except Exception as e:
            print("def login() 出现问题:" + str(e))
            return None


def getAlreadyCourse(session):
    already_select_course_list = []
    try:
        response = session.get(
            url=already_select_course_url, headers=header).text
        for each in json.loads(response)['xkxx'][0]:
            already_select_course_list.append(json.loads(
                response)['xkxx'][0][each]['courseName'])
        return already_select_course_list
    except Exception as e:
        print("def getAlreadyCourse() 出现问题:" + str(e))
        return None


def courseSelect(session, each_course, alreadySelectCourse, courseName, courseNum, coursekxhNum):
    if courseName not in (course for course in alreadySelectCourse) and courseNum == \
            each_course['kch'] and each_course['kxh'] in coursekxhNum.split():

        if each_course['bkskyl'] <= 0:
            print("\033[0;33;40m" + "课程名:" + each_course['kcm'] + " 教师:" +
                  each_course['skjs'] + " 课余量:" + str(each_course['bkskyl']) + "\033[0m")
        else:
            print("\033[0;32;40m" + "课程名:" + each_course['kcm'] + " 教师:" +
                  each_course['skjs'] + " 课余量:" + str(each_course['bkskyl']) + "\033[0m")

            kcm = each_course['kcm']  # 课程名
            kch = each_course['kch']  # 课程号
            kxh = each_course['kxh']  # 课序号
            status = queryTeacherJL(session, kch, kxh)
            if status is None:
                return
            kcms = getKcms(kcm + "(" + kch + "@" + kxh + ")")  # 获得编码后的课程信息
            course_name = kch + "@" + kxh + "@" + selectcourse_xueqi
            tokenValue = getTokenValue(session)
            if tokenValue is None:
                return
            select_data = {
                'dealType': 5,
                'fajhh': "",
                'kcIds': course_name,
                'kcms': kcms,
                'sj': '0_0',
                'searchtj': courseName,
                'kclbdm': '',
                'inputCode': '',
                'tokenValue': tokenValue
            }
            try:
                c = session.post(url=select_url, data=select_data).text
                print("选课状态：", c)
                return True

            except Exception as e:
                print("def courseSelect() 出现问题:" + str(e))
    else:
        pass

    return False


def getTokenValue(session):
    try:
        response = session.get(url=courseSelect_url, headers=header).text
        return re.compile("([a-fA-F0-9]{32})").findall(response)[0]
    except Exception as e:
        print("def getTokenValue() 出现问题:" + str(e))
        return None


def getKcms(kms):
    kcms = ""
    for each in kms:
        kcms += (str(ord(each)) + ",")
    return kcms


def getFreeCourseList(session, courseName):
    list_data = {
        'kcm': courseName,
        'xq': 0,
        'jc': 0,
        'kclbdm': ""
    }
    try:
        response = session.post(
            url=courseList_url, headers=header, data=list_data).content.decode()
        return json.loads(response)['rwRxkZlList']
    except Exception as e:
        print("def getFreeCourseList() 出现问题:" + str(e))
        return None


def queryTeacherJL(session, kch, kxh):
    data = {
        "id": selectcourse_xueqi + "@" + kch + "@" + kxh
    }
    try:
        response = session.post(url=queryTeacherJL_url,
                                data=data, headers=header).content.decode()
        if(response):
            return response
    except Exception as e:
        print("def queryTeacherJL() 出现问题:" + str(e))
        return None


def isSelectTime() -> bool:
    Now = time.strftime("%H:%M:%S", time.localtime())
    Now_time = date.datetime.strptime(Now, '%H:%M:%S')
    toSelect_0 = date.datetime.strptime(selectTime[0], '%H:%M:%S')
    toSelect_1 = date.datetime.strptime(selectTime[1], '%H:%M:%S')
    return (Now_time > toSelect_0) and (Now_time < toSelect_1)


def main(session):
    while True:
        # 下载验证码
        try:
            downloadCaptcha(session)
        except Exception as e:
            print("def downloadCaptcha() 出现问题:" + str(e))
            continue
        # 登录
        print("main")
        loginResponse = login(session)
        if loginResponse == "success":
            # 控制选课开始时间
            while not isSelectTime():
                print("当前时间:"+str(date.datetime.now().time()
                                  ).split('.')[0]+" 在非设置选课时间")
                expireSeconds = date.datetime.strptime(selectTime[0], '%H:%M:%S') - date.datetime.strptime(
                    time.strftime("%H:%M:%S", time.localtime()), '%H:%M:%S')
                print("将在", expireSeconds, "后准时开始抢课！")
                expireSeconds = expireSeconds.seconds
                expireSeconds -= 10
                startSecond = 11
                if expireSeconds >= 0:
                    time.sleep(expireSeconds)
                else:
                    startSecond = 11 + expireSeconds
                for i in range(startSecond, 0, -1):
                    print(i-1)
                    time.sleep(1)
            print("\033[0;33;40m抢课开始！ *_*\033[0m")
            break
        else:
            print("登陆失败！")
    clock = 1
    while True:
        print("\n正在第{}轮选课！".format(clock))
        # 先查询已选课程
        alreadySelectCourse = getAlreadyCourse(session)
        # 查询不到已选课程就重新查询
        if alreadySelectCourse is None:
            continue

        select_course_idx = []
        for i in range(len(courseNames)):
            if courseNames[i] in alreadySelectCourse:
                select_course_idx.append(i)
                print("\033[0;31;40m你已经选上了 %s ！\033[0m" % (courseNames[i]))
        updateCourse(select_course_idx)
        if len(courseNames) == 0:
            print("\033[0;33;40m选课完成 ^.^\033[0m")
            exit()

        for i in range(len(courseNames)):
            # 然后查询要选课程的课余量
            courseList = getFreeCourseList(session, courseNames[i])
            if courseList is None:
                continue
            # 如果这门课没有被选择开始选课
            for each_course in courseList:
                if courseSelect(session, each_course, alreadySelectCourse,
                                courseNames[i], courseNums[i], coursekxhNums[i]):
                    break
            time.sleep(random.uniform(2, 5))

        clock = clock + 1


# 更新课程情况，去除已经选择的课程
def updateCourse(select_course_idx):
    if len(select_course_idx) == 0:
        return
    global courseNames
    global courseNums
    global coursekxhNums
    new_courseNames = []
    new_courseNums = []
    new_coursekxhNums = []

    for i in range(len(courseNames)):
        if i in select_course_idx:
            continue
        new_courseNames.append(courseNames[i])
        new_courseNums.append(courseNums[i])
        new_coursekxhNums.append(coursekxhNums[i])

    courseNames = new_courseNames
    courseNums = new_courseNums
    coursekxhNums = new_coursekxhNums


# -*- coding: UTF-8 -*-
import ast
import json
import random
import re
import time
from PIL import Image

from config import *


def getToken(session):
    res = session.get(url=token_url, headers=header).content
    print(res)
    matchObj = re.findall(
        r'<input type="hidden" id="tokenValue" name="tokenValue" value="(.*)">', res.decode())
    if matchObj:
        return matchObj[0]
    else:
        print("Token获取失败")
        exit()


def downloadCaptcha(session):
    with open("captcha.jpg", "wb") as f:
        f.write(session.get(url=captcha_url, headers=header).content)

# 初始化OCR（仅识别，不检测文字框；适合验证码）

def login(session):
    token = getToken(session)
    print("your token is", token)
    print("进入login")
    cpaptcha_switch = input("是否尝试自动识别验证码?[y/n]")
    if cpaptcha_switch == 'y' or cpaptcha_switch == 'Y':
        import  muggle_ocr
        while True:
            with open("captcha.jpg", 'rb') as f:
                captcha_bytes = f.read()
                sdk = muggle_ocr.SDK(model_type=muggle_ocr.ModelType.Captcha)
                text = sdk.predict(image_bytes=captcha_bytes)
                pwd = j_password
                inner1 = hex_md5(pwd)  # MD5(pwd)
                part1 = hex_md5(inner1, "1.8")  # MD5(MD5(pwd) + "1.8")
                inner2 = hex_md5(pwd, "1.8")  # MD5(pwd + "1.8")
                part2 = hex_md5(inner2, "1.8")  # MD5(MD5(pwd+"1.8") + "1.8")
                encrypted_pwd = part1 + '*' + part2
                login_data = {
                    'tokenValue': token,
                    'j_username': j_username,
                    'j_password': encrypted_pwd,
                    'j_captcha': text
                }

                print("识别的验证码为:{}".format(text))

                try:
                    response = session.post(
                        url=login_url, headers=header, data=login_data).text
                    print(response)
                    if "高校教学管理与服务平台" in response:
                        print("登陆成功！")
                        return "success"
                    else:

                        print("自动识别验证码失败，三秒后准备尝试重新登录!")
                        time.sleep(3)
                        return "failed"

                except Exception as e:
                    print("def login() 出现问题:" + str(e))
                    return None
    else:
        img = Image.open('captcha.jpg')
        img.show()

        pwd = j_password
        inner1 = hex_md5(pwd)  # MD5(pwd)
        part1 = hex_md5(inner1, "1.8")  # MD5(MD5(pwd) + "1.8")
        inner2 = hex_md5(pwd, "1.8")  # MD5(pwd + "1.8")
        part2 = hex_md5(inner2, "1.8")  # MD5(MD5(pwd+"1.8") + "1.8")
        encrypted_pwd = part1 + '*' + part2
        login_data = {
            'tokenValue': token,
            'j_username': j_username,
            'j_password': encrypted_pwd,
            'j_captcha': input("请输入验证码:")
        }
        print(login_data)
        try:
            response = session.post(
                url=login_url, headers=header, data=login_data).text
            print(response)
            if "选课公告" in response:
                print("登陆成功！")
                return "success"
            else:
                return "failed"
        except Exception as e:
            print("def login() 出现问题:" + str(e))
            return None


def getAlreadyCourse(session):
    already_select_course_list = []
    try:
        response = session.get(
            url=already_select_course_url, headers=header).text
        for each in json.loads(response)['xkxx'][0]:
            already_select_course_list.append(json.loads(
                response)['xkxx'][0][each]['courseName'])
        return already_select_course_list
    except Exception as e:
        print("def getAlreadyCourse() 出现问题:" + str(e))
        return None


def courseSelect(session, each_course, alreadySelectCourse, courseName, courseNum, coursekxhNum):
    if courseName not in (course for course in alreadySelectCourse) and courseNum == \
            each_course['kch'] and each_course['kxh'] in coursekxhNum.split():

        if each_course['bkskyl'] <= 0:
            print("\033[0;33;40m" + "课程名:" + each_course['kcm'] + " 教师:" +
                  each_course['skjs'] + " 课余量:" + str(each_course['bkskyl']) + "\033[0m")
        else:
            print("\033[0;32;40m" + "课程名:" + each_course['kcm'] + " 教师:" +
                  each_course['skjs'] + " 课余量:" + str(each_course['bkskyl']) + "\033[0m")

            kcm = each_course['kcm']  # 课程名
            kch = each_course['kch']  # 课程号
            kxh = each_course['kxh']  # 课序号
            status = queryTeacherJL(session, kch, kxh)
            if status is None:
                return
            kcms = getKcms(kcm + "(" + kch + "@" + kxh + ")")  # 获得编码后的课程信息
            course_name = kch + "@" + kxh + "@" + selectcourse_xueqi
            tokenValue = getTokenValue(session)
            if tokenValue is None:
                return

            select_data = {
                'dealType': 5,
                'fajhh': "",
                'kcIds': course_name,
                'kcms': kcms,
                'sj': '0_0',
                'searchtj': courseName,
                'kclbdm': '',
                'inputCode': '',
                'tokenValue': tokenValue
            }
            try:
                c = session.post(url=select_url, data=select_data).text
                if "验证码" in c or "inputCode" in c or "不能为空" in c:
                    print("\033[0;31;40m触发验证码，需要手动输入！\033[0m")
                    # 下次需要输入验证码；


                print("选课状态：", c)
                return True

            except Exception as e:
                print("def courseSelect() 出现问题:" + str(e))
    else:
        pass

    return False


def getTokenValue(session):
    try:
        response = session.get(url=courseSelect_url, headers=header).text
        return re.compile("([a-fA-F0-9]{32})").findall(response)[0]
    except Exception as e:
        print("def getTokenValue() 出现问题:" + str(e))
        return None


def getKcms(kms):
    kcms = ""
    for each in kms:
        kcms += (str(ord(each)) + ",")
    return kcms


def getFreeCourseList(session, courseName):
    list_data = {
        'kcm': courseName,
        'xq': 0,
        'jc': 0,
        'kclbdm': ""
    }
    try:
        response = session.post(
            url=courseList_url, headers=header, data=list_data).content.decode()
        return json.loads(response)['rwRxkZlList']
    except Exception as e:
        print("def getFreeCourseList() 出现问题:" + str(e))
        return None


def queryTeacherJL(session, kch, kxh):
    data = {
        "id": selectcourse_xueqi + "@" + kch + "@" + kxh
    }
    try:
        response = session.post(url=queryTeacherJL_url,
                                data=data, headers=header).content.decode()
        if(response):
            return response
    except Exception as e:
        print("def queryTeacherJL() 出现问题:" + str(e))
        return None


def isSelectTime() -> bool:
    Now = time.strftime("%H:%M:%S", time.localtime())
    Now_time = date.datetime.strptime(Now, '%H:%M:%S')
    toSelect_0 = date.datetime.strptime(selectTime[0], '%H:%M:%S')
    toSelect_1 = date.datetime.strptime(selectTime[1], '%H:%M:%S')
    return (Now_time > toSelect_0) and (Now_time < toSelect_1)


def main(session):
    while True:
        # 下载验证码
        try:
            downloadCaptcha(session)
        except Exception as e:
            print("def downloadCaptcha() 出现问题:" + str(e))
            continue
        # 登录
        print("login")
        loginResponse = login(session)
        print(loginResponse)
        if loginResponse == "success":
            # 控制选课开始时间
            while not isSelectTime():
                print("当前时间:"+str(date.datetime.now().time()
                                  ).split('.')[0]+" 在非设置选课时间")
                expireSeconds = date.datetime.strptime(selectTime[0], '%H:%M:%S') - date.datetime.strptime(
                    time.strftime("%H:%M:%S", time.localtime()), '%H:%M:%S')
                print("将在", expireSeconds, "后准时开始抢课！")
                expireSeconds = expireSeconds.seconds
                expireSeconds -= 10
                startSecond = 11
                if expireSeconds >= 0:
                    time.sleep(expireSeconds)
                else:
                    startSecond = 11 + expireSeconds
                for i in range(startSecond, 0, -1):
                    print(i-1)
                    time.sleep(1)
            print("\033[0;33;40m抢课开始！ *_*\033[0m")
            break
        else:
            print("登陆失败！")
    clock = 1
    while True:
        print("\n正在第{}轮选课！".format(clock))
        # 先查询已选课程
        alreadySelectCourse = getAlreadyCourse(session)
        # 查询不到已选课程就重新查询
        if alreadySelectCourse is None:
            continue

        select_course_idx = []
        for i in range(len(courseNames)):
            if courseNames[i] in alreadySelectCourse:
                select_course_idx.append(i)
                print("\033[0;31;40m你已经选上了 %s ！\033[0m" % (courseNames[i]))
        updateCourse(select_course_idx)
        if len(courseNames) == 0:
            print("\033[0;33;40m选课完成 ^.^\033[0m")
            exit()

        for i in range(len(courseNames)):
            # 然后查询要选课程的课余量
            courseList = getFreeCourseList(session, courseNames[i])
            if courseList is None:
                continue
            # 如果这门课没有被选择开始选课
            for each_course in courseList:
                if courseSelect(session, each_course, alreadySelectCourse,
                                courseNames[i], courseNums[i], coursekxhNums[i]):
                    break
            time.sleep(random.uniform(1.5, 3))

        clock = clock + 1

# 更新课程情况，去除已经选择的课程


def updateCourse(select_course_idx):
    if len(select_course_idx) == 0:
        return
    global courseNames
    global courseNums
    global coursekxhNums
    new_courseNames = []
    new_courseNums = []
    new_coursekxhNums = []

    for i in range(len(courseNames)):
        if i in select_course_idx:
            continue
        new_courseNames.append(courseNames[i])
        new_courseNums.append(courseNums[i])
        new_coursekxhNums.append(coursekxhNums[i])

    courseNames = new_courseNames
    courseNums = new_courseNums
    coursekxhNums = new_coursekxhNums
