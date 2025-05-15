/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.ltlt.pojo;

import jakarta.persistence.Basic;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;
import jakarta.validation.constraints.Size;
import java.io.Serializable;
import java.util.Date;

/**
 *
 * @author aicon
 */
@Entity
@Table(name = "visitorcard")
@NamedQueries({
    @NamedQuery(name = "Visitorcard.findAll", query = "SELECT v FROM Visitorcard v"),
    @NamedQuery(name = "Visitorcard.findById", query = "SELECT v FROM Visitorcard v WHERE v.id = :id"),
    @NamedQuery(name = "Visitorcard.findByFullName", query = "SELECT v FROM Visitorcard v WHERE v.fullName = :fullName"),
    @NamedQuery(name = "Visitorcard.findByIdNumber", query = "SELECT v FROM Visitorcard v WHERE v.idNumber = :idNumber"),
    @NamedQuery(name = "Visitorcard.findByRelationship", query = "SELECT v FROM Visitorcard v WHERE v.relationship = :relationship"),
    @NamedQuery(name = "Visitorcard.findByRegisteredAt", query = "SELECT v FROM Visitorcard v WHERE v.registeredAt = :registeredAt")})
public class Visitorcard implements Serializable {

    private static final long serialVersionUID = 1L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Basic(optional = false)
    @Column(name = "id")
    private Integer id;
    @Size(max = 100)
    @Column(name = "full_name")
    private String fullName;
    @Size(max = 20)
    @Column(name = "id_number")
    private String idNumber;
    @Size(max = 50)
    @Column(name = "relationship")
    private String relationship;
    @Column(name = "registered_at")
    @Temporal(TemporalType.TIMESTAMP)
    private Date registeredAt;
    @JoinColumn(name = "user_id", referencedColumnName = "id")
    @ManyToOne
    private User userId;

    public Visitorcard() {
    }

    public Visitorcard(Integer id) {
        this.id = id;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getIdNumber() {
        return idNumber;
    }

    public void setIdNumber(String idNumber) {
        this.idNumber = idNumber;
    }

    public String getRelationship() {
        return relationship;
    }

    public void setRelationship(String relationship) {
        this.relationship = relationship;
    }

    public Date getRegisteredAt() {
        return registeredAt;
    }

    public void setRegisteredAt(Date registeredAt) {
        this.registeredAt = registeredAt;
    }

    public User getUserId() {
        return userId;
    }

    public void setUserId(User userId) {
        this.userId = userId;
    }

    @Override
    public int hashCode() {
        int hash = 0;
        hash += (id != null ? id.hashCode() : 0);
        return hash;
    }

    @Override
    public boolean equals(Object object) {
        // TODO: Warning - this method won't work in the case the id fields are not set
        if (!(object instanceof Visitorcard)) {
            return false;
        }
        Visitorcard other = (Visitorcard) object;
        if ((this.id == null && other.id != null) || (this.id != null && !this.id.equals(other.id))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "com.ltlt.pojo.Visitorcard[ id=" + id + " ]";
    }
    
}
