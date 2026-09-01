Describe 'Start-ZtProgressServer security' {
    BeforeAll {
        $serverPath = Join-Path $global:__testData.ModuleRoot 'private/progress/Start-ZtProgressServer.ps1'
        $serverSource = Get-Content -Path $serverPath -Raw
    }

    It 'binds the listener only to localhost' {
        $serverSource | Should -Match 'http://localhost:\$Port/'
        $serverSource | Should -Not -Match 'http://\+:'
        $serverSource | Should -Not -Match 'http://\*:'
    }

    It 'rejects requests whose remote endpoint is not loopback' {
        $serverSource | Should -Match '\[System\.Net\.IPAddress\]::IsLoopback\(\$request\.RemoteEndPoint\.Address\)'
        $serverSource | Should -Match '\$response\.StatusCode = 403'
    }

    It 'does not allow cross-origin browser requests' {
        $serverSource | Should -Not -Match 'Access-Control-Allow-Origin'
    }

    It 'sets browser hardening headers' {
        $serverSource | Should -Match 'Content-Security-Policy'
        $serverSource | Should -Match 'X-Content-Type-Options'
        $serverSource | Should -Match 'Referrer-Policy'
        $serverSource | Should -Match 'frame-ancestors ''none'''
    }
}
