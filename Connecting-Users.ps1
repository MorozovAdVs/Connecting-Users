clear

function Change-EnRuLayout ([string]$inString) {
	$Layout = @{
    [char]'q' = 'й'
    [char]'w' = 'ц'
    [char]'e' = 'у'
    [char]'r' = 'к'
    [char]'t' = 'е'
    [char]'y' = 'н'
    [char]'u' = 'г'
    [char]'i' = 'ш'
    [char]'o' = 'щ'
    [char]'p' = 'з'
    [char]'[' = 'х'
    [char]']' = 'ъ'
    [char]'a' = 'ф'
    [char]'s' = 'ы'
    [char]'d' = 'в'
    [char]'f' = 'а'
    [char]'g' = 'п'
    [char]'h' = 'р'
    [char]'j' = 'о'
    [char]'k' = 'л'
    [char]'l' = 'д'
    [char]';' = 'ж'
    [char]"`'" = 'э'
    [char]'z' = 'я'
    [char]'x' = 'ч'
    [char]'c' = 'с'
    [char]'v' = 'м'
    [char]'b' = 'и'
    [char]'n' = 'т'
    [char]'m' = 'ь'
    [char]',' = 'б'
    [char]'.' = 'ю'
    [char]'`' = 'ё'
    [char]'{' = 'х'
    [char]'}' = 'ъ'
    [char]':' = 'ж'
    [char]"`"" = 'э'
    [char]'<' = 'б'
    [char]'>' = 'ю'
    [char]'~' = 'ё'
    }
    $TranslitText =""
	$LowerinString = $inString.ToLower()
    foreach ($CHR in $inCHR = $LowerinString.ToCharArray()) {
        if ($Layout[$CHR]) {
            $TranslitText += $Layout[$CHR]
		}
        else {
			$TranslitText += $CHR
		}
    }
    return $TranslitText
}

function Get-ConnectableComputer {
    $searchfolder = 'OU=UserPC,OU=AllComps,DC=corp,DC=corp'
	$serv1 = 'term-serv01'
	$serv2 = 'term-serv02'
	$serv3 = 'term-serv03'
	$serv4 = 'term-serv04'
	$searchword = Read-Host("1: $serv1`n2: $serv2`n3: $serv3`n4: $serv4`nВведите имя пользователя или имя/IP компьютера или номер сервера")
    if ($searchword -ieq '\') {
		clear; break
	}
	elseif (-not $searchword) {
		return $null
	}
	elseif ($searchword -eq '1') {
		$computerslist = Get-ADComputer -Identity "$serv1" -Properties Description, DistinguishedName, IPv4Address
	}
	elseif ($searchword -eq '2') {
		$computerslist = Get-ADComputer -Identity "$serv2" -Properties Description, DistinguishedName, IPv4Address
	}
	elseif ($searchword -eq '3') {
		$computerslist = Get-ADComputer -Identity "$serv3" -Properties Description, DistinguishedName, IPv4Address
	}
	elseif ($searchword -eq '4') {
		$computerslist = Get-ADComputer -Identity "$serv4" -Properties Description, DistinguishedName, IPv4Address
	}
	elseif ($searchword.contains('.')) {
		$computerslist = Get-ADComputer -Filter {(enabled -eq $true) -and (IPv4Address -eq $searchword)} -SearchBase $searchfolder -Properties Description, DistinguishedName, IPv4Address
	}
	elseif ($searchword.contains('-')) {
		$searchword += '*'
		$computerslist = Get-ADComputer -Filter {(enabled -eq $true) -and (Name -like $searchword)} -SearchBase $searchfolder -Properties Description, DistinguishedName, IPv4Address
	}
	else {
		if ($searchword[0] -eq '#') {
			$searchword = $searchword.replace('#', '')
		}
		elseif ($searchword -match "[a-z]+") {
			$searchword = Change-EnRuLayout($searchword)
		}
		$searchword += '*'
		$computerslist = Get-ADComputer -Filter {(enabled -eq $true) -and (Description -like $searchword)} -SearchBase $searchfolder -Properties Description, DistinguishedName, IPv4Address
	}
	return $computerslist
}

function Choise-Computer ($comps) {
	$computerindex = 9999
	while (-not [bool]$comps[[int]$computerindex]){
		$computerindex = (Read-Host('Введите номер компьютера'))
        if ($computerindex -ieq '\') {
		    return '\'
        }
	}
	return $comps[[int]$computerindex]
}

function Choise-User ($comp) {
    $foundusers = (quser /server:$comp) -replace '\s{2,}', ',' | ConvertFrom-Csv | Select-Object Пользователь, ID, Статус
	if (-not [bool]$foundusers) {
		Write-Host('Нет активных пользователей на указанном компьютере.')
		pause
		return '\'
	}
    $selecteduser = ''
    $activefoundusers = $foundusers | Where-Object {$_.статус -eq 'активно'}
    if ($activefoundusers[1] -eq $NULL){return $activefoundusers.id}
    Write-Host($foundusers | Out-String)
    while (-not [bool]$selecteduser)  {
        $choise_id = Read-Host('Введите ID пользователя')
        if ($choise_id -ieq '\') {
		    return '\'
    }
        $selecteduser = $activefoundusers | Where-Object {$_.id -eq $choise_id}
    }
    return $selecteduser.id
}

while ($true) {
	$ConnectableComputers = Get-ConnectableComputer
	if (-not [bool]$ConnectableComputers) {
		Write-Output('Список пуст. Попробуйте ещё раз.')
		pause
		clear
		continue
	}
    $count = 0
    $ConnectableComputers | ForEach-Object {
        $_ |  Select-Object @{Name = 'Number'; Expression = {$count}}, Name, Ipv4Address, Description, DistinguishedName
        $count++
    } | Format-List
	if (($ConnectableComputers.gettype().name -eq 'Object[]') -and ($ConnectableComputers[0].gettype().name -eq 'ADComputer')) {
		$ConnectableComputers = Choise-Computer($ConnectableComputers)
        if ($ConnectableComputers -eq '\') {
            clear
		    continue
        }
	}
	if ($ConnectableComputers.gettype().name -eq 'ADComputer') {
		Write-Output("Проверка доступности...`n")
		$TestComputer = $ConnectableComputers.name
		try {
			Test-Connection ($TestComputer) -Count 1 -ErrorAction Stop
		}
		catch {
			Write-Output('Найденый компьютер недоступен. Попробуйте ещё раз.')
			pause
			clear
			continue
		}
		
		Write-Output("`nКомпьютер доступен.")
		$ConnectionParametr = Read-Host("1 - теневое подключение`n2 - копировать имя`n3 - удаленный powershell`n4 - открыть проводник`n5 - обычное подключение`nВведите способ подключения")
		
		if ($ConnectionParametr -ieq '\') {
        }
        elseif ($ConnectionParametr[0] -ieq '1') {
			$SelectedComputer = $ConnectableComputers.Name
			$id = Choise-User($SelectedComputer)
            if ($id -eq '\') {
                clear
                continue
            }
            $ShadowConnectionArguments = "/shadow:$id /v:$selectedcomputer /control /remoteGuard"
			MSG $id /server:$SelectedComputer /time:15 "Пользователь $env:USERNAME подключен к вашей сессии."
			Start-Process -FilePath mstsc.exe -ArgumentList $ShadowConnectionArguments -Wait
            MSG $id /server:$SelectedComputer /time:300 'Теневое подключение завершено.'
		}
		elseif ($ConnectionParametr[0] -ieq '2') {
			Set-Clipboard -Value $ConnectableComputers.Name
		}
		elseif ($ConnectionParametr[0] -ieq '3') {
			$SelectedComputer = $ConnectableComputers.Name
			cmd /C "sc \\$SelectedComputer start winrm" | Out-Null
			Write-Output("`nКомандлеты выполняются на $SelectedComputer`:`n")
			cmd /C "winrs -r:$SelectedComputer powershell -NoLogo"
		}
		elseif ($ConnectionParametr[0] -ieq '4') {
			$path = '\\' + $ConnectableComputers.Name + '\C$'
			explorer.exe $path
		}
		elseif ($ConnectionParametr[0] -ieq '5') {
			$SelectedComputer = $ConnectableComputers.Name
			mstsc.exe /v:($SelectedComputer) /remoteGuard
        }
	}
	else {
		Write-Output('Ошибка в выполнении скрипта.')
		pause
	}
	clear
}
