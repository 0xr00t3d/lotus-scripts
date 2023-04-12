-- AUTHOR: Mohamed Tarek @0xr00t3d
-- Reference: https://www.acunetix.com/vulnerabilities/web/svn-repository-found/

SCAN_TYPE = 2
PAYLOADS = {
    "/.svn",
}

function main()
    for _, path in pairs(PAYLOADS) do
        local new_url = HttpMessage:urlJoin(path)
        local status, resp = pcall(function()
            return http:send { "GET", url = new_url }
        end)

        if status == true and resp.status == 200 then
            Reports:add{
                name = "SVN DIR found",
                url = new_url,
                risk = "high",
                description = "https://www.acunetix.com/vulnerabilities/web/svn-repository-found",
                evidence = new_url,
            }

        end
    end
end
