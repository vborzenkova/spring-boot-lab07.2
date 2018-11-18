/*
 * This code is sample code, provided as-is, and we make no
 * warranties as to its correctness or suitability for
 * any purpose.
 *
 * We hope that it's useful to you.  Enjoy.
 * Copyright 2006-12 LearningPatterns Inc.
 */
 
package com.javatunes.web;

import java.util.Collection;

import com.javatunes.util.MusicItem;

public class Search {
	private String keyword;
	private Collection<MusicItem> results;
	private String artist;
	
	public String getArtist() {
		return artist;
	}
	public void setArtist(String artist) {
		this.artist = artist;
	}
	public String getKeyword() {
		return keyword;
	}
	public void setKeyword(String keyword) {
		this.keyword = keyword;
	}
	public Collection<MusicItem> getResults() {
		return results;
	}
	public void setResults(Collection<MusicItem> results) {
		this.results = results;
	}
	
	

}
