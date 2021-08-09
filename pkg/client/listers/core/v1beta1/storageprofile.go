/*
Copyright 2018 The CDI Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by lister-gen. DO NOT EDIT.

package v1beta1

import (
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	v1beta1 "kubevirt.io/containerized-data-importer/pkg/apis/core/v1beta1"
)

// StorageProfileLister helps list StorageProfiles.
// All objects returned here must be treated as read-only.
type StorageProfileLister interface {
	// List lists all StorageProfiles in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1beta1.StorageProfile, err error)
	// Get retrieves the StorageProfile from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1beta1.StorageProfile, error)
	StorageProfileListerExpansion
}

// storageProfileLister implements the StorageProfileLister interface.
type storageProfileLister struct {
	indexer cache.Indexer
}

// NewStorageProfileLister returns a new StorageProfileLister.
func NewStorageProfileLister(indexer cache.Indexer) StorageProfileLister {
	return &storageProfileLister{indexer: indexer}
}

// List lists all StorageProfiles in the indexer.
func (s *storageProfileLister) List(selector labels.Selector) (ret []*v1beta1.StorageProfile, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1beta1.StorageProfile))
	})
	return ret, err
}

// Get retrieves the StorageProfile from the index for a given name.
func (s *storageProfileLister) Get(name string) (*v1beta1.StorageProfile, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1beta1.Resource("storageprofile"), name)
	}
	return obj.(*v1beta1.StorageProfile), nil
}