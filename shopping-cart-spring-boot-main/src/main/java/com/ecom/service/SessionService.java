package com.ecom.service;

import com.ecom.model.Session;

public interface SessionService {

    Session saveSession(Session session);

    Session getSession(Integer id);

}
