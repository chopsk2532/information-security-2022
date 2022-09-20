# Enigma Template Code for CNU Information Security 2022
# Resources from https://www.cryptomuseum.com/crypto/enigma

# This Enigma code implements Enigma I, which is utilized by
# Wehrmacht and Luftwaffe, Nazi Germany.
# This version of Enigma does not contain wheel settings, skipped for
# adjusting difficulty of the assignment.

from copy import deepcopy
from ctypes import ArgumentError

# Enigma Components
ETW = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

WHEELS = {
    "I": {
        "wire": "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
        "turn": 16
    },
    "II": {
        "wire": "AJDKSIRUXBLHWTMCQGZNPYFVOE",
        "turn": 4
    },
    "III": {
        "wire": "BDFHJLCPRTXVZNYEIWGAKMUSQO",
        "turn": 21
    }
}

UKW = {
    "A": "EJMZALYXVBWFCRQUONTSPIKHGD",
    "B": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "C": "FVPJIAOYEDRZXWGCTKUQSBNMHL"
}

# Enigma Settings
SETTINGS = {
    "UKW": None,
    "WHEELS": [],
    "WHEEL_POS": [],
    "ETW": ETW,
    "PLUGBOARD": [],
    "TURN": [1, 1, 1]
}


def apply_settings(ukw, wheel, wheel_pos, plugboard):
    if not ukw in UKW:
        raise ArgumentError(f"UKW {ukw} does not exist!")
    SETTINGS["UKW"] = UKW[ukw]

    wheels = wheel.split(' ')
    for wh in wheels:
        if not wh in WHEELS:
            raise ArgumentError(f"WHEEL {wh} does not exist!")
        SETTINGS["WHEELS"].append(WHEELS[wh])

    wheel_poses = wheel_pos.split(' ')
    for wp in wheel_poses:
        if not wp in ETW:
            raise ArgumentError(f"WHEEL position must be in A-Z!")
        SETTINGS["WHEEL_POS"].append(ord(wp) - ord('A'))

    plugboard_setup = plugboard.split(' ')
    for ps in plugboard_setup:
        if not len(ps) == 2 or not ps.isupper():
            raise ArgumentError(f"Each plugboard setting must be sized in 2 and caplitalized; {ps} is invalid")
        SETTINGS["PLUGBOARD"].append(ps)


# Enigma Logics Start

# Plugboard
def pass_plugboard(input):

    for plug in SETTINGS["PLUGBOARD"]:
        if str.startswith(plug, input):
            return plug[1]
        elif str.endswith(plug, input):
            return plug[0]

    return input


# ETW
def pass_etw(input):
    return SETTINGS["ETW"][ord(input) - ord('A')]


# Wheels
def pass_wheels(input, reverse=False):
    # Implement Wheel Logics
    # Keep in mind that reflected signals pass wheels in reverse order

    #정뱡향인 경우
    #Wheel_position을 사용하여 설정된 값만큼 더해서 계산
    if not reverse:
        first = ord(input) - ord('A') + SETTINGS["WHEEL_POS"][2]
        #알파벳은 총 26자이기 때문에 그에 따른 범위를 적용
        if first > 25:
            first = first - 26
        elif first < 0:
            first = first + 26
        else:
            first = first
        pass_alpabet_1 = SETTINGS["WHEELS"][2]["wire"][first]

        #2번째 로터부터는 이전의 로터와의 Wheel_position 차이를 계산해서 그 값만큼 더해서 계산
        #이전의 로터보다 wheel_position이 크면 값이 증가, 작으면 값이 감소
        second = ord(pass_alpabet_1) - ord('A') + (SETTINGS["WHEEL_POS"][1] - SETTINGS["WHEEL_POS"][2])
        if second > 25:
            second = second - 26
        elif second < 0:
            second = second + 26
        else:
            second = second
        pass_alpabet_2 = SETTINGS["WHEELS"][1]["wire"][second]

        third = ord(pass_alpabet_2) - ord('A') + (SETTINGS["WHEEL_POS"][0] - SETTINGS["WHEEL_POS"][1])
        if third > 25:
            third = third - 26
        elif third < 0:
            third = third + 26
        else:
            third = third

        pass_alpabet_3 = SETTINGS["WHEELS"][0]["wire"][third]

        #마지막 로터에서 나와 utw로 들어가는 알파벳의 경우 마지막 로터의 wheel_position만큼의 값을 빼서
        #position 위치를 초기화시킨 뒤 알파벳을 변환시켜 입력
        utw_input = ord(pass_alpabet_3) - ord('A') - SETTINGS["WHEEL_POS"][0]
        if utw_input > 25:
            utw_input = utw_input - 26
        elif utw_input < 0:
            utw_input = utw_input + 26
        else:
            utw_input = utw_input
        utw_input_alpabet = ETW[utw_input]
        return utw_input_alpabet

    #역방향
    #wheel_position을 이용해 이전 로터의 알파벳 값을 변환시킨 뒤 사용
    else:
        first = ord(input) - ord('A') + SETTINGS["WHEEL_POS"][0]
        if first > 25:
            first = first - 26
        elif first < 0:
            first = first + 26
        else:
            first = first

        #역방향의 경우 해당 알파벳이 로터의 알파벳 배열에서 몇 번째 알파벳인지 계산하여 그 순서를 저장한 뒤
        #그 순서에 맞는 원래 알파벳 배열에서 값을 찾아 출력
        pass_alpabet_1 = ETW[first]
        num_1 = SETTINGS["WHEELS"][0]["wire"].find(pass_alpabet_1)
        out_alpabet_1 = ETW[num_1]

        second = ord(out_alpabet_1) - ord('A') + (SETTINGS["WHEEL_POS"][1] - SETTINGS["WHEEL_POS"][0])
        if second > 25:
            second = second - 26
        elif second < 0:
            second = second + 26
        else:
            second = second
        pass_alpabet_2 = ETW[second]
        num_2 = SETTINGS["WHEELS"][1]["wire"].find(pass_alpabet_2)
        out_alpabet_2 = ETW[num_2]

        third = ord(out_alpabet_2) - ord('A') + (SETTINGS["WHEEL_POS"][2] - SETTINGS["WHEEL_POS"][1])
        if third > 25:
            third = third - 26
        elif third < 0:
            third = third + 26
        else:
            third = third
        pass_alpabet_3 = ETW[third]
        num_3 = SETTINGS["WHEELS"][2]["wire"].find(pass_alpabet_3)
        out_alpabet_3 = ETW[num_3]

        final = ord(out_alpabet_3) - ord('A') - SETTINGS["WHEEL_POS"][2]
        if final > 25:
            final = final - 26
        elif final < 0:
            final = final + 26
        else:
            final = final
        fianl_alpabet = ETW[final]
        return fianl_alpabet


# UKW
def pass_ukw(input):
    return SETTINGS["UKW"][ord(input) - ord('A')]


# Wheel Rotation
def rotate_wheels():
    # Implement Wheel Rotation Logics

    #SETTINGS 값에 "TURN"이라는 배열을 추가하여 rotate_wheel을 구현

    #현재 로터의 Turn이 로터의 설정 turn과 같다면 그 로터의 turn이 다 돈 것이므로
    #다음 로터의 turn이 +1 된다.
    if SETTINGS["WHEELS"][2]["turn"] == SETTINGS["TURN"][2]:
        SETTINGS["TURN"][2] = 0
        SETTINGS["TURN"][1] += 1
        #wheel_position의 값이 25라면 그 로터가 한 바퀴(26개의 알파벳)을 돈 것이므로
        #wheel_position을 'A'로 초기화 시킨다.
        if SETTINGS["WHEEL_POS"][1] == 25:
            SETTINGS["WHEEL_POS"][1] = 0
        else:
            SETTINGS["WHEEL_POS"][1] += 1
    else:
        SETTINGS["TURN"][2] += 1

    if SETTINGS["WHEEL_POS"][2] == 25:
        SETTINGS["WHEEL_POS"][2] = 0
    else:
        SETTINGS["WHEEL_POS"][2] += 1

    if SETTINGS["WHEELS"][1]["turn"] == SETTINGS["TURN"][1]:
        SETTINGS["TURN"][1] = 0
        SETTINGS["TURN"][0] += 1
        if SETTINGS["WHEEL_POS"][0] == 25:
            SETTINGS["WHEEL_POS"][0] = 0
        else:
            SETTINGS["WHEEL_POS"][0] += 1

    if SETTINGS["WHEELS"][0]["turn"] == SETTINGS["TURN"][0]:
        SETTINGS["TURN"][0] = 0

    pass


# Enigma Exec Start
plaintext = input("Plaintext to Encode: ")
ukw_select = input("Set Reflector (A, B, C): ")
wheel_select = input("Set Wheel Sequence L->R (I, II, III): ")
wheel_pos_select = input("Set Wheel Position L->R (A~Z): ")
plugboard_setup = input("Plugboard Setup: ")

apply_settings(ukw_select, wheel_select, wheel_pos_select, plugboard_setup)

for ch in plaintext:

    rotate_wheels()
    encoded_ch = ch

    encoded_ch = pass_plugboard(encoded_ch)
    encoded_ch = pass_etw(encoded_ch)
    encoded_ch = pass_wheels(encoded_ch)
    encoded_ch = pass_ukw(encoded_ch)
    encoded_ch = pass_wheels(encoded_ch, reverse=True)
    encoded_ch = pass_plugboard(encoded_ch)

    print(encoded_ch, end='')
