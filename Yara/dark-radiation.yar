rule DarkRadiation
{
  meta:
    author: "Adam Burnett; @InfosecEagle; alburnett[at]gmail{.}com"
    description: "I can't remember where I saw what report for this one; sorry, bad tracking on my part."

  strings:
    $str1 = "eval \"$Az$Bz$Cz$Dz$Ez$Fz$Gz$Hz$Iz$Jz$$Kz$Lz$Mz$Nz$Oz$Pz$Qz$Rz$Sz$Tz$Uz$Vz$Wz$Xz$Yz$Zz" ascii
    $str2 = "\";pRz='TM';RMz='-e';EIz=' c';vEz='IL'; gQz='ON';" ascii
    $str3 = "Я запутал его с помощью пакета npm bahs-onfuscate, но начал тормозить. Ответ нужно ждать 10-15 секунд" ascii

  condition:
    any of them
}
