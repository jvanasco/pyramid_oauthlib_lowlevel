<html>
<head></head>
<body>
    <h3>Authorize App</h3>

    % if request.workspace.OAuth2Error:
        <div class="alert alert-danger">
            <b>Error!</b> There was an error processsing your request.
        </div>
    % endif

    <table class="table table-striped table-condensed">
        <tbody>
            <tr>
                <th>App Name</th>
                <td>
                    <code>${request.workspace.oAuth2_ValidityDict['request'].client.app_name_unique}</code>
                </td>
            </tr>
            <tr>
                <th>App Description</th>
                <td>
                    ${request.workspace.oAuth2_ValidityDict['request'].client.app_description}
                </td>
            </tr>
            <tr>
                <th>App Website</th>
                <td>
                    <a href="${request.workspace.oAuth2_ValidityDict['request'].client.app_website}"
                        target="_blank"
                    >
                        <i class="fa fa-external-link"></i>
                        ${request.workspace.oAuth2_ValidityDict['request'].client.app_website}
                    </a>
                </td>
            </tr>
            <tr>
                <th>Permissions</th>
                <td>${', '.join(request.workspace.oAuth2_ValidityDict['scopes'])}</td>
            </tr>
            <tr>
                <th>State</th>
                <td><code>${request.workspace.oAuth2_ValidityDict['state']}</code></td>
            </tr>
            <tr>
                <th></th>
                <td>
                    <form action="/authority/oauth2/flow-a/authorization" method="POST" id="app-action-authorize">
                        <% form = request.pyramid_formencode_classic.get_form('authorize') %>
                        ${form.html_error_placeholder('Error_Main_authorize')|n}
                        ${form.csrf_input_field(type="hidden", csrf_token=get_csrf_token())|n}
                        <input type="hidden" name="scope" value="${' '.join(request.workspace.oAuth2_ValidityDict['scopes'])}"/>
                        <input type="hidden" name="client_id" value="${request.workspace.oAuth2_ValidityDict['client_id']}"/>
                        <input type="hidden" name="redirect_uri" value="${request.workspace.oAuth2_ValidityDict['redirect_uri']}"/>
                        <input type="hidden" name="response_type" value="${request.workspace.oAuth2_ValidityDict['response_type']}"/>
                        <input type="hidden" name="state" value="${request.workspace.oAuth2_ValidityDict['state']}"/>
                        <input type="submit" name="submit" class="btn btn-success" value="authorize"/>
                    </form>
                </td>
            </tr>
        </tbody>
    </table>
</body>
</html>
