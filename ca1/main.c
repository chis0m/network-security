
undefined8 main(int param_1,undefined8 *param_2)

{
  bool bVar1;
  int iVar2;
  char *pcVar3;
  undefined7 extraout_var;
  FILE *__stream;
  undefined8 uVar4;
  long in_FS_OFFSET;
  char local_1418 [1024];
  char local_1018 [4104];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_1 == 3) {
    iVar2 = strcmp((char *)param_2[1],"-f");
    if (iVar2 == 0) {
      pcVar3 = realpath((char *)param_2[2],local_1018);
      if (pcVar3 == (char *)0x0) {
        perror("realpath");
      }
      else {
        bVar1 = starts_with(local_1018,"/home/mark/confs/");
        if ((int)CONCAT71(extraout_var,bVar1) == 0) {
          fprintf(stderr,"Access denied: config must be inside %s\n","/home/mark/confs/");
        }
        else {
          __stream = fopen(local_1018,"r");
          if (__stream == (FILE *)0x0) {
            perror("fopen");
          }
          else {
            do {
              pcVar3 = fgets(local_1418,0x400,__stream);
              if (pcVar3 == (char *)0x0) {
                fclose(__stream);
                execl("/usr/sbin/apache2ctl","apache2ctl",&DAT_00102072,local_1018,0);
                perror("execl failed");
                goto LAB_00101663;
              }
              uVar4 = is_unsafe_line(local_1418);
            } while ((int)uVar4 == 0);
            fwrite("Blocked: Config includes unsafe directive.\n",1,0x2b,stderr);
            fclose(__stream);
          }
        }
      }
      goto LAB_00101663;
    }
  }
  fprintf(stderr,"Usage: %s -f /home/mark/confs/file.conf\n",*param_2);
LAB_00101663:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 1;
}

