# pwnable.tw_applestore
#fake ebp #leak stack address using libc_environ

libc릭이 가능한데, 스택부분의 릭도 이를 이용해서 가능하다.   
libc의 environ에는 스택의 주소가 들어가 있기 때문에 이를 이용해서 fake ebp기법을 사용한다. 
fake ebp기법으로 libc릭으로 알아낸 system주소를 넣어서 clear!  

아이다로 구조체 사용하는 것에 익숙해지자!
atoi로 4를 넣어주려고 했는데  
0x08040a34이렇게 중간에 엔터가 들어가 있지 않아도 0x08040b34처럼 주어도 4로 인식했다  
![image]https://user-images.githubusercontent.com/24853452/55663292-34a2e300-5857-11e9-96ae-89defc7fb6e4.png  
