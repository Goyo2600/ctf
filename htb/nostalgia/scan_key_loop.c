void scan_key_loop(void)

{
  uint *puVar1;
  undefined4 extraout_r1;
  undefined2 *puVar2;
  ushort scan_key;
  int iVar3;
  undefined4 uVar4;
  ushort *mask_keys_buffer;
  undefined8 uVar5;
  char *key_text;
  ushort mask_key_value;
  
  DISPCNT = 0x1140;
  FUN_08000a74();
  FUN_08000ce4(1);
  DISPCNT = 0x404;
  FUN_08000dd0((int)&DAT_02009584,&g_VideoRAM,(ushort *)&DAT_030000dc);
  FUN_08000354((int)&DAT_030000dc,0x3c);
  scan_key = g_scankey;
  do {
    g_scan_key_copy = scan_key;
    g_scankey = KEYINPUT | 0xfc00;
    mask_keys_buffer = &g_mask_keys_buffer;
    scan_key = g_scankey;
    do {
      puVar1 = DAT_030004dc;
      mask_key_value = *mask_keys_buffer;
      if ((mask_key_value & g_scan_key_copy & ~scan_key) != 0) {
                    /* select */
        if (mask_key_value == 4) {
          key_num_total = 0;
          uVar5 = FUN_08001c24(DAT_030004dc);
          FUN_08001868(puVar1,0,(uint)uVar5);
          uVar4 = 0x1483;
          g_BG_PaletteRAM = 0x1483;
          puVar2 = &g_BG_PaletteRAM;
          iprintf((int *)&Format_Erase_Entire_Screen,extraout_r1,&g_BG_PaletteRAM,0x1483);
          iprintf((int *)&Format_Locate_at_Line10Column4,&NULL,puVar2,uVar4);
          g_checkValue = 0;
          scan_key = g_scankey;
        }
        else {
                    /* Start */
          if (mask_key_value == 8) {
            if (g_checkValue == 0xf3) {
              DISPCNT = 0x404;
              FUN_08000dd0((int)&DAT_02008aac,&g_VideoRAM,(ushort *)&DAT_030000dc);
              FUN_08000354((int)&DAT_030000dc,0x3c);
              scan_key = g_scankey;
            }
          }
          else if (key_num_total < 8) {
            key_num_total = key_num_total + 1;
            FUN_08000864();
                    /* Right */
            if (mask_key_value == 0x10) {
              g_checkValue = g_checkValue + 0x3a;
LAB_08001742:
              key_text = &Text_RT;
            }
            else if (mask_key_value < 0x11) {
                    /* Button A */
              if (mask_key_value == 1) {
                g_checkValue = g_checkValue + 3;
LAB_08001766:
                key_text = &Text_A;
              }
              else {
                iVar3 = 0xe;
                if (mask_key_value != 2) {
LAB_0800168a:
                  iVar3 = 0;
                }
                g_checkValue = iVar3 + g_checkValue;
                if (mask_key_value == 0x20) {
LAB_080016ea:
                  key_text = &Text_LT;
                }
                else if (mask_key_value < 0x21) {
                    /* Button B */
                  if (mask_key_value == 2) {
                    key_text = &Text_B;
                  }
                  else {
                    /* Right */
                    if (mask_key_value == 0x10) goto LAB_08001742;
                    /* Button A */
                    if (mask_key_value == 1) goto LAB_08001766;
                  }
                }
                else {
                    /* Down */
                  if (mask_key_value == 0x80) goto LAB_08001754;
                  if (mask_key_value < 0x81) {
                    /* Up */
                    if (mask_key_value == 0x40) goto LAB_08001778;
                  }
                  else {
                    /* Button R */
                    if (mask_key_value == 0x100) {
                      key_text = &Text_R;
                    }
                    else {
                    /* Button L */
                      if (mask_key_value == 0x200) {
                        key_text = &Text_L;
                      }
                    }
                  }
                }
              }
            }
            else {
                    /* Up */
              if (mask_key_value == 0x40) {
                g_checkValue = g_checkValue + 0x28;
LAB_08001778:
                key_text = &Text_UP;
              }
              else {
                if (mask_key_value != 0x80) {
                  if (mask_key_value != 0x20) goto LAB_0800168a;
                  g_checkValue = g_checkValue + 0x6e;
                  goto LAB_080016ea;
                }
                g_checkValue = g_checkValue + 0xc;
LAB_08001754:
                key_text = &Text_DN;
              }
            }
            uVar5 = strcat(DAT_030004dc,key_text);
            uVar4 = 0x1483;
            g_BG_PaletteRAM = 0x1483;
            puVar2 = &g_BG_PaletteRAM;
            DAT_030004dc = (uint *)uVar5;
            iprintf((int *)&Format_Erase_Entire_Screen,(int)((ulonglong)uVar5 >> 0x20),
                    &g_BG_PaletteRAM,0x1483);
            iprintf((int *)&Format_Locate_at_Line10Column4,(uint *)uVar5,puVar2,uVar4);
            scan_key = g_scankey;
          }
        }
      }
      mask_keys_buffer = mask_keys_buffer + 1;
    } while (mask_keys_buffer != (ushort *)&mask_key_buffer_end);
  } while( true );
}
