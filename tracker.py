import re

def is_mbr(mbr):
    if mbr[510] == 0x55 and mbr[511] == 0xAA: # MBR의 Magic ID 판별
        return True
    else:
        return False


def convert_byte_to_int(bytes):
    '''byte를 리틀엔디안 형식으로 읽어서 int로 형변환하는 함수'''

    return int.from_bytes(bytes, 'little', signed=False)    # 리틀-엔디안


def is_mft(mft):
    if mft[0:4].decode('ascii') == 'FILE':
        return True
    else:
        return False


def mft_intergrity_check(mft):
    ''' fixup array를 이용한 무결성 검사 '''

    mft_header = mft[0:48]
    offset_to_fixup_array = mft_header[4:6]
    int_fixup = int.from_bytes(offset_to_fixup_array, 'little', signed=False)

    if mft[int_fixup:int_fixup + 2] == mft[510:512] and mft[int_fixup:int_fixup + 2] == mft[1022:1024]:
        return True
    else:
        return False

def mft_name(mft):
    ''' mft 속성을 읽고 해당하는 이름을 출력하는 함수 '''

    entry_name = ['MFTMirr','LogFile','Voulume','AttrDef','Bitmap','Boot',\
                  'BadClus','Secure','UpCase','Extend','Objld','Quota','Reparse',\
                  'UsrJrnl']

    for name in entry_name:
        result = re.findall(name, str(mft[160::2]))
        if result != []:
            return 'File Name: {}'.format(result[0])

    return 'File Name: X'

if __name__ == "__main__":
    target = input().replace('"', '')
    # target = 'c:/NTFS Partition Recovery.001'

    print('┌─' + '─' * len(target) + '─┐')
    print('│ ' + target + ' │')
    print('└─' + '─' * len(target) + '─┘')

    master_br = open(target, 'rb')  # C드라이브 루트에 존재하는 ntfs 파일을 이진 읽기 모드로 파일을 open
    master_br.seek(0)  # 파일의 맨 앞으로 이동
    target_mbr = master_br.read(512)  # mbr에 512바이트만큼 저장
    master_br.close()

    if is_mbr(target_mbr):
        print('>> MBR Read Success !! <<')
        print('【 MBR 】')
        start_of_br = convert_byte_to_int(target_mbr[454:458])
        print('Start of BR: {} Sector'.format(start_of_br))  # BR 시작 주소 sector

        # 파일 다시 열어서 br 영역 확인
        boot_record = open(target, 'rb')
        boot_record.seek(512 * start_of_br)  # 섹터 이동
        target_br = boot_record.read(512)  # br 영역만큼 저장
        boot_record.close()

        print('------------------------------')
        print('【 BR 】')
        start_of_mft = convert_byte_to_int(target_br[48:56])

        print('OEM Name:', target_br[3:11].decode('ascii'))
        print('Sector Per Cluster:', target_br[13]) # br[13] 위치는 Sector Per Cluster

        mft_entry_start = start_of_br + start_of_mft * target_br[13]   # br 주소 + (MFT 시작 주소 * SP)
        print('Start of MFT: {} Sector'.format(mft_entry_start))


        print('------------------------------')
        print('【 MFT 】')
        mft_entry = open(target, 'rb')
        mft_entry.seek(512 * mft_entry_start)  # 섹터 이동
        target_mft = mft_entry.read(1024)  # mft entry 영역만큼 저장
        mft_entry.close()


        print('▷ 0번 ENTRY')
        if mft_intergrity_check(target_mft):
            print('>> Integrity verification !! <<')
            print('File Name: MFT')
            print()

        number = 1
        while number < 24:
            # 파일 다시 열어서 mft entry 1~23 영역 확인
            mft_entry = open(target, 'rb')
            mft_entry.seek(512 * (mft_entry_start + number * 2))  # n번 Entry 섹터 이동
            target_mft = mft_entry.read(1024)  # mft entry 영역만큼 저장
            mft_entry.close()

            if is_mft(target_mft):
                print('▷ {}번 ENTRY'.format(number))

                if mft_intergrity_check(target_mft):
                    print('>> Integrity verification !! <<')    # 무결성 검사
                    print(mft_name(target_mft))
                else:
                    print('>> Integrity verification Fail <<')

            else:
                print('▷ {}번 ENTRY'.format(number))
                print('Signature Error')
                print('Empty Space')

            if number == 5:
                print('File Name: root dir') # 루트 디렉터리 위치

            if number in range(16,24): # 예약 영역
                print('Reserved Space')

            number += 1
            print()

    else:
        print('MBR Read Fail')

input()