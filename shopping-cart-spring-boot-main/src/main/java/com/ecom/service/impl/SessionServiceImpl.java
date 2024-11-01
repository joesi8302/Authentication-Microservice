package com.ecom.service.impl;

import com.ecom.model.Session;
import com.ecom.repository.SessionRepository;
import com.ecom.service.SessionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class SessionServiceImpl implements SessionService {

    @Autowired
    SessionRepository sessionRepository;

    @Override
    public Session saveSession(Session session) {
        return sessionRepository.save(session);
    }

    @Override
    public Session getSession(Integer id) {
        return sessionRepository.findById(id).orElse(null);
    }
}
