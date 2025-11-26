from app.services.ca_service import ca_service


def test_root_marked_online_when_last_intermediate_removed(db_session):
    created = ca_service.initialize_hierarchy(
        db_session,
        common_name="Internal Root CA",
        organization="Test Org",
        offline_root=True,
        create_intermediate=True,
    )

    root = ca_service.get_root_ca(db_session)
    assert root is not None
    assert root.is_offline is True

    intermediate = next(ca for ca in created if not ca.is_root)
    ca_service.delete_ca(db_session, intermediate)

    active = ca_service.get_active_issuing_ca(db_session)
    assert active is not None
    assert active.is_root is True
    assert active.is_offline is False

    refreshed_root = ca_service.get_root_ca(db_session)
    assert refreshed_root is not None
    assert refreshed_root.is_offline is False
