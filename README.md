# Connecting-Users
Скрипт для подключения к пользователям.

Скрипт позволяет подключаться к пользователям по:
1) Части фамилии пользователя (последнему зашедшему на компьютер), при этом меняет раскладку введенного текста фамилии.
	 Чтобы отключить автоматическую замену, перед фамилией нужно добавить #, например: '#Morozov'.
2) Части имени компьютера.
3) Полному IP-адресу.
3) Цифре быстрого набора.
Поиск ведется в заданной в $searchfolder OU.

Позволяет:
1) Подключиться теневой сессией с разрешения ползователя.
2) Копировать имя целевого компьютера.
3) Открыть сессию PS на удаленном компьютере с отключенным WinRM.
4) Открыть проводник на C: удаленного компьютера (если диски расшарены по домену).
5) Подключиться по RDP со своими учетными данными.


Для отмены выбора введите \ на любом этапе подлкючения к пользователю.

Для работы скрипта необходимо быть локальным администатором удаленного компьютера и активация политики, отвечающей за разрешение подключения теневой сессии.
А также разрешение на локальном компьютере на выполнение скриптов и модуль для работы с AD в PS (командлеты в файле Install-Module.ps1).
