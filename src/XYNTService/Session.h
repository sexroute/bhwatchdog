template<class ResourceType>


class wts_resource
{
	ResourceType * m_pResource;
public:
	wts_resource()
		: m_pResource(0)
	{
	}

	wts_resource(ResourceType * pResource)
		: m_pResource( pResource )
	{
	}

	~wts_resource()
	{
		if (m_pResource)
			WTSFreeMemory(m_pResource);
	}

	void reset(ResourceType * pResource = 0)
	{
		ResourceType * pOldResource = m_pResource;
		m_pResource = pResource;
		if (pOldResource)
			WTSFreeMemory(pOldResource);
	}
	const ResourceType * get() const { return m_pResource; }
	ResourceType * get() { return m_pResource; }

	ResourceType * release()
	{
		ResourceType * pRes = m_pResource;
		m_pResource = 0;
		return pRes;
	}

	ResourceType * operator -> ()   {   return m_pResource;    }
	const ResourceType * operator -> () const {   return m_pResource;    }
	ResourceType & operator * ()   {   return *m_pResource;    }
	const ResourceType & operator * () const {   return *m_pResource;    }

	const ResourceType & operator [] (int i) {   return m_pResource[i];    }
	const ResourceType & operator () (int i) const {   return m_pResource[i];    }

private:
	wts_resource(wts_resource & otherResource)
		: m_pResource( otherResource.get() )
	{
		otherResource.m_pResource = 0;
	}

};

