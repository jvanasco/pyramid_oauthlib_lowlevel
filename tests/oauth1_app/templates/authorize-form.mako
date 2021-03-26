<html>
<head></head>
<body>
    <h3>Authorize App</h3>

    % if request.workspace.OAuth1Error:
        <div class="alert alert-danger">
            <b>Error!</b> There was an error processsing your request.
        </div>
    % endif

    <table class="table table-striped table-condensed">
        <tbody>
            % if False:
                <tr>
                    <th>App ID</th>
                    <td><code>${request.workspace.oAuth1_TokenRequest.client.client_key}</code></td>
                </tr>
            % endif
            <tr>
                <th>App Name</th>
                <td>
                    <code>${request.workspace.oAuth1_TokenRequest.client.app_name_unique}</code>
                </td>
            </tr>
            <tr>
                <th>App Description</th>
                <td>
                    ${request.workspace.oAuth1_TokenRequest.client.app_description}
                </td>
            </tr>
            <tr>
                <th>App Website</th>
                <td>
                    <a href="${request.workspace.oAuth1_TokenRequest.client.app_website}"
                        target="_blank"
                    >
                        <i class="fa fa-external-link"></i>
                        ${request.workspace.oAuth1_TokenRequest.client.app_website}
                    </a>
                </td>
            </tr>
            <tr>
                <th>Permissions</th>
                <td>${', '.join(request.workspace.oAuth1_TokenRequest.realms)}</td>
            </tr>
            <tr>
                <th>Request Timestamp</th>
                <td>${request.workspace.oAuth1_TokenRequest.timestamp_created}</td>
            </tr>
            <tr>
                <th>Token</th>
                <td><code>${request.workspace.oAuth1_TokenRequest.oauth_token}</code></td>
            </tr>
            <tr>
                <th></th>
                <td>
                    <form action="/authority/oauth1/authorize" method="POST" id="app-action-authorize">
                        <% form = request.pyramid_formencode_classic.get_form('authorize') %>
                        ${form.html_error_placeholder('Error_Main_authorize')|n}
                        ${form.csrf_input_field(type="hidden", csrf_token=get_csrf_token())|n}
                        <input type="hidden" name="oauth_token" value="${request.workspace.oAuth1_TokenRequest.oauth_token}"/>
                        <input type="submit" name="submit" class="btn btn-success" value="authorize"/>
                    </form>
                    <hr/>
                    <form action="/authority/oauth1/authorize" method="POST" id="app-action-deny">>
                        <% form = request.pyramid_formencode_classic.get_form('deny') %>
                        ${form.html_error_placeholder('Error_Main_deny')|n}
                        ${form.csrf_input_field(type="hidden", csrf_token=get_csrf_token())|n}
                        <input type="hidden" name="oauth_token" value="${request.workspace.oAuth1_TokenRequest.oauth_token}"/>
                        <input type="submit" name="submit" class="btn btn-danger" value="deny"/>
                    </form>

                </td>
            </tr>
        </tbody>
    </table>
</body>
</html>
