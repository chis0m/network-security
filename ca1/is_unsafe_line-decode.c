undefined8 is_unsafe_line(undefined8 param_1)

{
  bool bVar1;
  int iVar2;
  undefined8 uVar3;
  undefined7 extraout_var;
  long in_FS_OFFSET;
  char local_1038 [32];
  char local_1018 [4104];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  iVar2 = __isoc99_sscanf(param_1,"%31s %1023s",local_1038,local_1018);
  if (iVar2 != 2) {
    uVar3 = 0;
    goto LAB_00101423;
  }
  iVar2 = strcmp(local_1038,"Include");
  if (iVar2 == 0) {
LAB_001013c6:
    if (local_1018[0] == '/') {
      bVar1 = starts_with(local_1018,"/home/mark/confs/");
      if ((int)CONCAT71(extraout_var,bVar1) == 0) {
        fprintf(stderr,"[!] Blocked: %s is outside of %s\n",local_1018,"/home/mark/confs/");
        uVar3 = 1;
        goto LAB_00101423;
      }
    }
  }
  else {
    iVar2 = strcmp(local_1038,"IncludeOptional");
    if (iVar2 == 0) goto LAB_001013c6;
    iVar2 = strcmp(local_1038,"LoadModule");
    if (iVar2 == 0) goto LAB_001013c6;
  }
  uVar3 = 0;
LAB_00101423:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar3;
}
