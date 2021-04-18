package edu.uoc.elc.spring.lti.security;

import edu.uoc.elc.lti.tool.Tool;
import edu.uoc.elc.spring.lti.tool.ToolDefinitionBean;
import edu.uoc.elc.spring.lti.tool.ToolFactory;
import edu.uoc.elc.spring.lti.security.utils.TokenFactory;
import lombok.Getter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.Attributes2GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAttributes2GrantedAuthoritiesMapper;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.stream.Collectors;

/**
 * AuthenticationDetailsSource from LTI
 *
 * @author xaracil@uoc.edu
 */
public class LTIAuthenticationDetailsSource implements AuthenticationDetailsSource<HttpServletRequest, PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails> {
	private final Log logger = LogFactory.getLog(this.getClass());

	private final Attributes2GrantedAuthoritiesMapper ltiUserRoles2GrantedAuthoritiesMapper = new SimpleAttributes2GrantedAuthoritiesMapper();

	private final ToolDefinitionBean toolDefinitionBean;

	@Getter
	private Tool tool;

	public LTIAuthenticationDetailsSource() {
		this(null);
	}

	public LTIAuthenticationDetailsSource(ToolDefinitionBean toolDefinitionBean) {
		this.toolDefinitionBean = toolDefinitionBean;
	}

	protected Collection<String> getUserRoles(HttpServletRequest request) {
		ArrayList<String> ltiUserRolesList = new ArrayList<>();
		ToolFactory toolFactory = new ToolFactory();
		if (this.logger.isDebugEnabled()) {
			String resultSet =
					request.getParameterMap().entrySet()
							.stream()
							.map(e -> e.getKey() + "=" + String.join(", ", e.getValue()))
							.collect(Collectors.joining(" "));
			this.logger.debug(request.getSession().getId() + " " + request.getRequestURI() + " results query " + resultSet);
		}
		this.tool = toolFactory.from(toolDefinitionBean, request);

		String token = TokenFactory.from(request);
		String state = request.getParameter("state");
		tool.validate(token, state);

		if (tool.isValid()) {
			ltiUserRolesList.add("USER");
		}

		if (tool.isLearner()) {
			ltiUserRolesList.add("LEARNER");
		}

		if (tool.isInstructor()) {
			ltiUserRolesList.add("INSTRUCTOR");
		}

		return ltiUserRolesList;
	}

	@Override
	public PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails buildDetails(HttpServletRequest httpServletRequest) {
		Collection<String> ltiUserRoles = this.getUserRoles(httpServletRequest);
		final Collection<? extends GrantedAuthority> userGas = this.ltiUserRoles2GrantedAuthoritiesMapper.getGrantedAuthorities(ltiUserRoles);
		if (this.logger.isDebugEnabled()) {
			this.logger.debug("LTI roles [" + ltiUserRoles + "] mapped to Granted Authorities: [" + userGas + "]");
		}

		return new PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(httpServletRequest, userGas);
	}
}
